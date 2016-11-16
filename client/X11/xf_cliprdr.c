/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * X11 Clipboard Redirection
 *
 * Copyright 2010-2011 Vic Lee
 * Copyright 2015 Thincast Technologies GmbH
 * Copyright 2015 DI (FH) Martin Haimberger <martin.haimberger@thincast.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <X11/Xlib.h>
#include <X11/Xatom.h>

#ifdef WITH_XFIXES
#include <X11/extensions/Xfixes.h>
#endif

#include <winpr/crt.h>
#include <winpr/image.h>
#include <winpr/stream.h>
#include <winpr/clipboard.h>

#include <freerdp/log.h>
#include <freerdp/client/cliprdr.h>
#include <freerdp/channels/channels.h>

#include "xf_cliprdr.h"

#define TAG CLIENT_TAG("x11")

#define MAX_CLIPBOARD_FORMATS	255

struct xf_cliprdr_format
{
	Atom atom;
	UINT32 formatId;
	char* formatName;
};
typedef struct xf_cliprdr_format xfCliprdrFormat;

struct xf_clipboard
{
	xfContext* xfc;
	rdpChannels* channels;
	CliprdrClientContext* context;

	wClipboard* system;

	Window root_window;
	Atom clipboard_atom;
	Atom property_atom;

	Atom raw_transfer_atom;
	Atom raw_format_list_atom;

	int numClientFormats;
	xfCliprdrFormat clientFormats[20];

	int numServerFormats;
	CLIPRDR_FORMAT* serverFormats;

	int numTargets;
	Atom targets[20];

	int requestedFormatId;

	BYTE* data;
	BOOL data_raw_format;
	UINT32 data_format_id;
	const char* data_format_name;
	int data_length;
	XEvent* respond;

	Window owner;
	BOOL sync;

	/* INCR mechanism */
	Atom incr_atom;
	BOOL incr_starts;
	BYTE* incr_data;
	int incr_data_length;

	/* XFixes extension */
	int xfixes_event_base;
	int xfixes_error_base;
	BOOL xfixes_supported;
	
	// Moxel
	BOOL need_cp1251;
};

UINT xf_cliprdr_send_client_format_list(xfClipboard* clipboard);

static void xf_cliprdr_check_owner(xfClipboard* clipboard)
{
	Window owner;
	xfContext* xfc = clipboard->xfc;

	if (clipboard->sync)
	{
		owner = XGetSelectionOwner(xfc->display, clipboard->clipboard_atom);

		if (clipboard->owner != owner)
		{
			clipboard->owner = owner;
			xf_cliprdr_send_client_format_list(clipboard);
		}
	}
}

static BOOL xf_cliprdr_is_self_owned(xfClipboard* clipboard)
{
	xfContext* xfc = clipboard->xfc;
	return XGetSelectionOwner(xfc->display,
	                          clipboard->clipboard_atom) == xfc->drawable;
}

static void xf_cliprdr_set_raw_transfer_enabled(xfClipboard* clipboard,
        BOOL enabled)
{
	UINT32 data = enabled;
	xfContext* xfc = clipboard->xfc;
	XChangeProperty(xfc->display, xfc->drawable, clipboard->raw_transfer_atom,
	                XA_INTEGER, 32, PropModeReplace, (BYTE*) &data, 1);
}

static BOOL xf_cliprdr_is_raw_transfer_available(xfClipboard* clipboard)
{
	Atom type;
	int format;
	int result = 0;
	unsigned long length;
	unsigned long bytes_left;
	UINT32* data = NULL;
	UINT32 is_enabled = 0;
	Window owner = None;
	xfContext* xfc = clipboard->xfc;
	owner = XGetSelectionOwner(xfc->display, clipboard->clipboard_atom);

	if (owner != None)
	{
		result = XGetWindowProperty(xfc->display, owner,
		                            clipboard->raw_transfer_atom, 0, 4, 0, XA_INTEGER,
		                            &type, &format, &length, &bytes_left, (BYTE**) &data);
	}

	if (data)
	{
		is_enabled = *data;
		XFree(data);
	}

	if ((owner == None) || (owner == xfc->drawable))
		return FALSE;

	if (result != Success)
		return FALSE;

	return is_enabled ? TRUE : FALSE;
}

static BOOL xf_cliprdr_formats_equal(const CLIPRDR_FORMAT* server,
                                     const xfCliprdrFormat* client)
{
	if (server->formatName && client->formatName)
	{
		/* The server may be using short format names while we store them in full form. */
		return (0 == strncmp(server->formatName, client->formatName,
		                     strlen(server->formatName)));
	}

	if (!server->formatName && !client->formatName)
	{
		return (server->formatId == client->formatId);
	}

	return FALSE;
}

static xfCliprdrFormat* xf_cliprdr_get_client_format_by_id(
    xfClipboard* clipboard, UINT32 formatId)
{
	int index;
	xfCliprdrFormat* format;

	for (index = 0; index < clipboard->numClientFormats; index++)
	{
		format = &(clipboard->clientFormats[index]);

		if (format->formatId == formatId)
			return format;
	}

	return NULL;
}

static xfCliprdrFormat* xf_cliprdr_get_client_format_by_atom(
    xfClipboard* clipboard, Atom atom)
{
	int i;
	xfCliprdrFormat* format;

	for (i = 0; i < clipboard->numClientFormats; i++)
	{
		format = &(clipboard->clientFormats[i]);

		if (format->atom == atom)
			return format;
	}

	return NULL;
}

static CLIPRDR_FORMAT* xf_cliprdr_get_server_format_by_atom(
    xfClipboard* clipboard, Atom atom)
{
	int i, j;
	xfCliprdrFormat* client_format;
	CLIPRDR_FORMAT* server_format;

	for (i = 0; i < clipboard->numClientFormats; i++)
	{
		client_format = &(clipboard->clientFormats[i]);

		if (client_format->atom == atom)
		{
			for (j = 0; j < clipboard->numServerFormats; j++)
			{
				server_format = &(clipboard->serverFormats[j]);

				if (xf_cliprdr_formats_equal(server_format, client_format))
					return server_format;
			}
		}
	}

	return NULL;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT xf_cliprdr_send_data_request(xfClipboard* clipboard,
        UINT32 formatId)
{
	CLIPRDR_FORMAT_DATA_REQUEST request;
	ZeroMemory(&request, sizeof(CLIPRDR_FORMAT_DATA_REQUEST));
	request.requestedFormatId = formatId;
	return clipboard->context->ClientFormatDataRequest(clipboard->context,
	        &request);
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT xf_cliprdr_send_data_response(xfClipboard* clipboard, BYTE* data,
        int size)
{
	CLIPRDR_FORMAT_DATA_RESPONSE response;
	ZeroMemory(&response, sizeof(CLIPRDR_FORMAT_DATA_RESPONSE));
	response.msgFlags = (data) ? CB_RESPONSE_OK : CB_RESPONSE_FAIL;
	response.dataLen = size;
	response.requestedFormatData = data;
	return clipboard->context->ClientFormatDataResponse(clipboard->context,
	        &response);
}

static wStream* xf_cliprdr_serialize_server_format_list(xfClipboard* clipboard)
{
	UINT32 i;
	UINT32 formatCount;
	wStream* s = NULL;

	/* Typical MS Word format list is about 80 bytes long. */
	if (!(s = Stream_New(NULL, 128)))
	{
		WLog_ERR(TAG, "failed to allocate serialized format list");
		goto error;
	}

	/* If present, the last format is always synthetic CF_RAW. Do not include it. */
	formatCount = (clipboard->numServerFormats > 0) ? clipboard->numServerFormats -
	              1 : 0;
	Stream_Write_UINT32(s, formatCount);

	for (i = 0; i < formatCount; i++)
	{
		CLIPRDR_FORMAT* format = &clipboard->serverFormats[i];
		size_t name_length = format->formatName ? strlen(format->formatName) : 0;

		if (!Stream_EnsureRemainingCapacity(s, sizeof(UINT32) + name_length + 1))
		{
			WLog_ERR(TAG, "failed to expand serialized format list");
			goto error;
		}

		Stream_Write_UINT32(s, format->formatId);
		Stream_Write(s, format->formatName, name_length);
		Stream_Write_UINT8(s, '\0');
	}

	Stream_SealLength(s);
	return s;
error:
	Stream_Free(s, TRUE);
	return NULL;
}

static CLIPRDR_FORMAT* xf_cliprdr_parse_server_format_list(BYTE* data,
        size_t length, UINT32* numFormats)
{
	UINT32 i;
	wStream* s = NULL;
	CLIPRDR_FORMAT* formats = NULL;

	if (!(s = Stream_New(data, length)))
	{
		WLog_ERR(TAG, "failed to allocate stream for parsing serialized format list");
		goto error;
	}

	if (Stream_GetRemainingLength(s) < sizeof(UINT32))
	{
		WLog_ERR(TAG, "too short serialized format list");
		goto error;
	}

	Stream_Read_UINT32(s, *numFormats);

	if (*numFormats > MAX_CLIPBOARD_FORMATS)
	{
		WLog_ERR(TAG, "unexpectedly large number of formats: %u", *numFormats);
		goto error;
	}

	if (!(formats = (CLIPRDR_FORMAT*) calloc(*numFormats, sizeof(CLIPRDR_FORMAT))))
	{
		WLog_ERR(TAG, "failed to allocate format list");
		goto error;
	}

	for (i = 0; i < *numFormats; i++)
	{
		const char* formatName = NULL;
		size_t formatNameLength = 0;

		if (Stream_GetRemainingLength(s) < sizeof(UINT32))
		{
			WLog_ERR(TAG, "unexpected end of serialized format list");
			goto error;
		}

		Stream_Read_UINT32(s, formats[i].formatId);
		formatName = (const char*) Stream_Pointer(s);
		formatNameLength = strnlen(formatName, Stream_GetRemainingLength(s));

		if (formatNameLength == Stream_GetRemainingLength(s))
		{
			WLog_ERR(TAG, "missing terminating null byte, %zu bytes left to read",
			         formatNameLength);
			goto error;
		}

		formats[i].formatName = strndup(formatName, formatNameLength);
		Stream_Seek(s, formatNameLength + 1);
	}

	Stream_Free(s, FALSE);
	return formats;
error:
	Stream_Free(s, FALSE);
	free(formats);
	*numFormats = 0;
	return NULL;
}

static void xf_cliprdr_free_formats(CLIPRDR_FORMAT* formats, UINT32 numFormats)
{
	UINT32 i;

	for (i = 0; i < numFormats; i++)
	{
		free(formats[i].formatName);
	}

	free(formats);
}

static CLIPRDR_FORMAT* xf_cliprdr_get_raw_server_formats(xfClipboard* clipboard,
        UINT32* numFormats)
{
	Atom type = None;
	int format = 0;
	unsigned long length = 0;
	unsigned long remaining;
	BYTE* data = NULL;
	CLIPRDR_FORMAT* formats = NULL;
	xfContext* xfc = clipboard->xfc;
	*numFormats = 0;
	XGetWindowProperty(xfc->display, clipboard->owner,
	                   clipboard->raw_format_list_atom,
	                   0, 4096, False, clipboard->raw_format_list_atom, &type, &format,
	                   &length, &remaining, &data);

	if (data && length > 0 && format == 8
	    && type == clipboard->raw_format_list_atom)
	{
		formats = xf_cliprdr_parse_server_format_list(data, length, numFormats);
	}
	else
	{
		WLog_ERR(TAG,
		         "failed to retrieve raw format list: data=%p, length=%lu, format=%d, type=%d (expected=%d)",
		         data, length, format, type, clipboard->raw_format_list_atom);
	}

	if (data)
		XFree(data);

	return formats;
}

static CLIPRDR_FORMAT* xf_cliprdr_get_formats_from_targets(
    xfClipboard* clipboard, UINT32* numFormats)
{
	int i;
	Atom atom;
	BYTE* data = NULL;
	int format_property;
	unsigned long length;
	unsigned long bytes_left;
	xfCliprdrFormat* format = NULL;
	CLIPRDR_FORMAT* formats = NULL;
	xfContext* xfc = clipboard->xfc;
	*numFormats = 0;
	XGetWindowProperty(xfc->display, xfc->drawable, clipboard->property_atom,
	                   0, 200, 0, XA_ATOM, &atom, &format_property, &length, &bytes_left, &data);

	if (length > 0)
	{
		if (!data)
		{
			WLog_ERR(TAG, "XGetWindowProperty set length = %d but data is NULL", length);
			goto out;
		}

		if (!(formats = (CLIPRDR_FORMAT*) calloc(length, sizeof(CLIPRDR_FORMAT))))
		{
			WLog_ERR(TAG, "failed to allocate %d CLIPRDR_FORMAT structs", length);
			goto out;
		}
	}

	for (i = 0; i < length; i++)
	{
		atom = ((Atom*) data)[i];
		format = xf_cliprdr_get_client_format_by_atom(clipboard, atom);

		if (format)
		{
			formats[*numFormats].formatId = format->formatId;
			formats[*numFormats].formatName = _strdup(format->formatName);
			*numFormats += 1;
		}
	}

out:

	if (data)
		XFree(data);

	return formats;
}

static CLIPRDR_FORMAT* xf_cliprdr_get_client_formats(xfClipboard* clipboard,
        UINT32* numFormats)
{
	CLIPRDR_FORMAT* formats = NULL;
	*numFormats = 0;

	if (xf_cliprdr_is_raw_transfer_available(clipboard))
	{
		formats = xf_cliprdr_get_raw_server_formats(clipboard, numFormats);
	}

	if (*numFormats == 0)
	{
		xf_cliprdr_free_formats(formats, *numFormats);
		formats = xf_cliprdr_get_formats_from_targets(clipboard, numFormats);
	}

	return formats;
}

static void xf_cliprdr_provide_server_format_list(xfClipboard* clipboard)
{
	wStream* formats = NULL;
	xfContext* xfc = clipboard->xfc;
	formats = xf_cliprdr_serialize_server_format_list(clipboard);

	if (formats)
	{
		XChangeProperty(xfc->display, xfc->drawable, clipboard->raw_format_list_atom,
		                clipboard->raw_format_list_atom, 8, PropModeReplace,
		                Stream_Buffer(formats), Stream_Length(formats));
	}
	else
	{
		XDeleteProperty(xfc->display, xfc->drawable, clipboard->raw_format_list_atom);
	}

	Stream_Free(formats, TRUE);
}

static void xf_cliprdr_get_requested_targets(xfClipboard* clipboard)
{
	UINT32 numFormats = 0;
	CLIPRDR_FORMAT* formats = NULL;
	CLIPRDR_FORMAT_LIST formatList;
	formats = xf_cliprdr_get_client_formats(clipboard, &numFormats);
	ZeroMemory(&formatList, sizeof(CLIPRDR_FORMAT_LIST));
	formatList.msgFlags = CB_RESPONSE_OK;
	formatList.numFormats = numFormats;
	formatList.formats = formats;
	clipboard->context->ClientFormatList(clipboard->context, &formatList);
	xf_cliprdr_free_formats(formats, numFormats);
}

static void unicode_to_cp1251(char *out, UINT16 in) { //Moxel
	int i;
	const int table[256] = { 
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
    0x0008, 0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F,
    0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017,
    0x0018, 0x0019, 0x001A, 0x001B, 0x001C, 0x001D, 0x001E, 0x001F,
    0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
    0x0028, 0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
    0x0038, 0x0039, 0x003A, 0x003B, 0x003C, 0x003D, 0x003E, 0x003F,
    0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
    0x0048, 0x0049, 0x004A, 0x004B, 0x004C, 0x004D, 0x004E, 0x004F,
    0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,
    0x0058, 0x0059, 0x005A, 0x005B, 0x005C, 0x005D, 0x005E, 0x005F,
    0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
    0x0068, 0x0069, 0x006A, 0x006B, 0x006C, 0x006D, 0x006E, 0x006F,
    0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
    0x0078, 0x0079, 0x007A, 0x007B, 0x007C, 0x007D, 0x007E, 0x0020,
    0x0402, 0x0403, 0x201A, 0x0453, 0x201E, 0x2026, 0x2020, 0x2021,
    0x20AC, 0x2030, 0x0409, 0x2039, 0x040A, 0x040C, 0x040B, 0x040F,
    0x0452, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x0020, 0x2122, 0x0459, 0x203A, 0x045A, 0x045C, 0x045B, 0x045F,
    0x00A0, 0x040E, 0x045E, 0x0408, 0x00A4, 0x0490, 0x00A6, 0x00A7,
    0x0401, 0x00A9, 0x0404, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x0407,
    0x00B0, 0x00B1, 0x0406, 0x0456, 0x0491, 0x00B5, 0x00B6, 0x00B7,
    0x0451, 0x2116, 0x0454, 0x00BB, 0x0458, 0x0405, 0x0455, 0x0457,
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417,
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F,
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427,
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F,
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437,
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F,
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447,
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F
	};
	*out=0;
	for (i = 0; i < 256; i++) 
	{
		UINT16 v = table[i];
		if (v==in) {
			*out=(BYTE)i;
			break;
		}
	}	
}

static void xf_cliprdr_process_requested_data(xfClipboard* clipboard,
        BOOL hasData, BYTE* data, int size)
{
	BOOL bSuccess;
	UINT32 SrcSize;
	UINT32 DstSize;
	UINT32 srcFormatId;
	UINT32 dstFormatId;
	BYTE* pSrcData = NULL;
	BYTE* pDstData = NULL;
	xfCliprdrFormat* format;

    //Moxel
	char* cp1251_buf;
	char cp1251_char[1];
	UINT16* unicode_char;
	WCHAR* unicode_buf = NULL;
	int unicode_size;
	int x;	

	if (clipboard->incr_starts && hasData)
		return;

	format = xf_cliprdr_get_client_format_by_id(clipboard,
	         clipboard->requestedFormatId);

	if (!hasData || !data || !format)
	{
		xf_cliprdr_send_data_response(clipboard, NULL, 0);
		return;
	}

	srcFormatId = 0;
	dstFormatId = 0;

	switch (format->formatId)
	{
		case CF_RAW:
			srcFormatId = CF_RAW;
			break;

		case CF_TEXT:
		case CF_OEMTEXT:
		case CF_UNICODETEXT:
			size = strlen((char*) data) + 1;
			srcFormatId = ClipboardGetFormatId(clipboard->system, "UTF8_STRING");
			break;

		case CF_DIB:
			srcFormatId = ClipboardGetFormatId(clipboard->system, "image/bmp");
			break;

		case CB_FORMAT_HTML:
			size = strlen((char*) data) + 1;
			srcFormatId = ClipboardGetFormatId(clipboard->system, "text/html");
			break;
	}
    
    if (clipboard->need_cp1251) {
		WLog_ERR(TAG, "Need convert to cp1251");
		srcFormatId=13;
		unicode_size = ConvertToUnicode(CP_UTF8, 0, (LPCSTR) data, -1, &unicode_buf, 0);
		SrcSize = (UINT32) unicode_size;
		pSrcData = (BYTE*) malloc(SrcSize);
		ZeroMemory(pSrcData, SrcSize);
		if (!pSrcData) return;
		cp1251_buf = (char*) pSrcData;
		unicode_char = unicode_buf;
		for (x = 0; x < unicode_size; x++) {
			unicode_to_cp1251(cp1251_char,*unicode_char);
			unicode_char++;
			*cp1251_buf++=(char)*cp1251_char;
		}
		free(unicode_buf);
		srcFormatId=13;
	} else {
    
	    SrcSize = (UINT32) size;
	    pSrcData = (BYTE*) malloc(SrcSize);
		if (!pSrcData) return;
		CopyMemory(pSrcData, data, SrcSize);
	}

	bSuccess = ClipboardSetData(clipboard->system, srcFormatId, (void*) pSrcData, SrcSize);
	
	if (!bSuccess)
		free(pSrcData);

	if (format->formatName)
		dstFormatId = ClipboardGetFormatId(clipboard->system, format->formatName);
	else
		dstFormatId = format->formatId;

	if (bSuccess)
	{
		DstSize = 0;
		pDstData = (BYTE*) ClipboardGetData(clipboard->system, dstFormatId, &DstSize);
	}

	if (!pDstData)
	{
		xf_cliprdr_send_data_response(clipboard, NULL, 0);
		return;
	}

	xf_cliprdr_send_data_response(clipboard, pDstData, (int) DstSize);
	free(pDstData);
}

static BOOL xf_cliprdr_get_requested_data(xfClipboard* clipboard, Atom target)
{
	Atom type;
	BYTE* data = NULL;
	BOOL has_data = FALSE;
	int format_property;
	unsigned long dummy;
	unsigned long length;
	unsigned long bytes_left;
	xfCliprdrFormat* format;
	xfContext* xfc = clipboard->xfc;
	format = xf_cliprdr_get_client_format_by_id(clipboard,
	         clipboard->requestedFormatId);

	if (!format || (format->atom != target))
	{
		xf_cliprdr_send_data_response(clipboard, NULL, 0);
		return FALSE;
	}

	XGetWindowProperty(xfc->display, xfc->drawable,
	                   clipboard->property_atom, 0, 0, 0, target,
	                   &type, &format_property, &length, &bytes_left, &data);

	if (data)
	{
		XFree(data);
		data = NULL;
	}

	if (bytes_left <= 0 && !clipboard->incr_starts)
	{
	}
	else if (type == clipboard->incr_atom)
	{
		clipboard->incr_starts = TRUE;

		if (clipboard->incr_data)
		{
			free(clipboard->incr_data);
			clipboard->incr_data = NULL;
		}

		clipboard->incr_data_length = 0;
		has_data = TRUE; /* data will be followed in PropertyNotify event */
	}
	else
	{
		if (bytes_left <= 0)
		{
			/* INCR finish */
			data = clipboard->incr_data;
			clipboard->incr_data = NULL;
			bytes_left = clipboard->incr_data_length;
			clipboard->incr_data_length = 0;
			clipboard->incr_starts = 0;
			has_data = TRUE;
		}
		else if (XGetWindowProperty(xfc->display, xfc->drawable,
		                            clipboard->property_atom, 0, bytes_left, 0, target,
		                            &type, &format_property, &length, &dummy, &data) == Success)
		{
			if (clipboard->incr_starts)
			{
				BYTE* new_data;
				bytes_left = length * format_property / 8;
				new_data = (BYTE*) realloc(clipboard->incr_data,
				                           clipboard->incr_data_length + bytes_left);

				if (!new_data)
					return FALSE;

				clipboard->incr_data = new_data;
				CopyMemory(clipboard->incr_data + clipboard->incr_data_length, data,
				           bytes_left);
				clipboard->incr_data_length += bytes_left;
				XFree(data);
				data = NULL;
			}

			has_data = TRUE;
		}
		else
		{
		}
	}

	XDeleteProperty(xfc->display, xfc->drawable, clipboard->property_atom);
	xf_cliprdr_process_requested_data(clipboard, has_data, data, (int) bytes_left);

	if (data)
		XFree(data);

	return TRUE;
}

static void xf_cliprdr_append_target(xfClipboard* clipboard, Atom target)
{
	int i;

	if (clipboard->numTargets >= ARRAYSIZE(clipboard->targets))
		return;

	for (i = 0; i < clipboard->numTargets; i++)
	{
		if (clipboard->targets[i] == target)
			return;
	}

	clipboard->targets[clipboard->numTargets++] = target;
}

static void xf_cliprdr_provide_targets(xfClipboard* clipboard, XEvent* respond)
{
	xfContext* xfc = clipboard->xfc;

	if (respond->xselection.property != None)
	{
		XChangeProperty(xfc->display, respond->xselection.requestor,
		                respond->xselection.property, XA_ATOM, 32, PropModeReplace,
		                (BYTE*) clipboard->targets, clipboard->numTargets);
	}
}

static void xf_cliprdr_provide_data(xfClipboard* clipboard, XEvent* respond,
                                    BYTE* data, UINT32 size)
{
	xfContext* xfc = clipboard->xfc;

	if (respond->xselection.property != None)
	{
		XChangeProperty(xfc->display, respond->xselection.requestor,
		                respond->xselection.property, respond->xselection.target,
		                8, PropModeReplace, data, size);
	}
}

static BOOL xf_cliprdr_process_selection_notify(xfClipboard* clipboard,
        XEvent* xevent)
{
	if (xevent->xselection.target == clipboard->targets[1])
	{
		if (xevent->xselection.property == None)
		{
			xf_cliprdr_send_client_format_list(clipboard);
		}
		else
		{
			xf_cliprdr_get_requested_targets(clipboard);
		}

		return TRUE;
	}
	else
	{
		return xf_cliprdr_get_requested_data(clipboard, xevent->xselection.target);
	}
}

static BOOL xf_cliprdr_process_selection_request(xfClipboard* clipboard,
        XEvent* xevent)
{
	int fmt;
	Atom type;
	UINT32 formatId;
	const char* formatName;
	XEvent* respond;
	BYTE* data = NULL;
	BOOL delayRespond;
	BOOL rawTransfer;
	unsigned long length;
	unsigned long bytes_left;
	CLIPRDR_FORMAT* format;
	xfContext* xfc = clipboard->xfc;

	if (xevent->xselectionrequest.owner != xfc->drawable)
		return FALSE;

	delayRespond = FALSE;

	if (!(respond = (XEvent*) calloc(1, sizeof(XEvent))))
	{
		WLog_ERR(TAG, "failed to allocate XEvent data");
		return FALSE;
	}

	respond->xselection.property = None;
	respond->xselection.type = SelectionNotify;
	respond->xselection.display = xevent->xselectionrequest.display;
	respond->xselection.requestor = xevent->xselectionrequest.requestor;
	respond->xselection.selection = xevent->xselectionrequest.selection;
	respond->xselection.target = xevent->xselectionrequest.target;
	respond->xselection.time = xevent->xselectionrequest.time;

	if (xevent->xselectionrequest.target == clipboard->targets[0]) /* TIMESTAMP */
	{
		/* TODO */
	}
	else if (xevent->xselectionrequest.target ==
	         clipboard->targets[1]) /* TARGETS */
	{
		/* Someone else requests our available formats */
		respond->xselection.property = xevent->xselectionrequest.property;
		xf_cliprdr_provide_targets(clipboard, respond);
	}
	else
	{
		format = xf_cliprdr_get_server_format_by_atom(clipboard,
		         xevent->xselectionrequest.target);

		if (format && (xevent->xselectionrequest.requestor != xfc->drawable))
		{
			formatId = format->formatId;
			formatName = format->formatName;
			rawTransfer = FALSE;

			if (formatId == CF_RAW)
			{
				if (XGetWindowProperty(xfc->display, xevent->xselectionrequest.requestor,
				                       clipboard->property_atom, 0, 4, 0, XA_INTEGER,
				                       &type, &fmt, &length, &bytes_left, &data) != Success)
				{
				}

				if (data)
				{
					rawTransfer = TRUE;
					CopyMemory(&formatId, data, 4);
					XFree(data);
				}
			}

			if ((clipboard->data != 0) && (formatId == clipboard->data_format_id)
			    && (formatName == clipboard->data_format_name))
			{
				/* Cached clipboard data available. Send it now */
				respond->xselection.property = xevent->xselectionrequest.property;
				xf_cliprdr_provide_data(clipboard, respond, clipboard->data,
				                        clipboard->data_length);
			}
			else if (clipboard->respond)
			{
				/* duplicate request */
			}
			else
			{
				/**
				 * Send clipboard data request to the server.
				 * Response will be postponed after receiving the data
				 */
				if (clipboard->data)
				{
					free(clipboard->data);
					clipboard->data = NULL;
				}

				respond->xselection.property = xevent->xselectionrequest.property;
				clipboard->respond = respond;
				clipboard->data_format_id = formatId;
				clipboard->data_format_name = formatName;
				clipboard->data_raw_format = rawTransfer;
				delayRespond = TRUE;
				xf_cliprdr_send_data_request(clipboard, formatId);
			}
		}
	}

	if (!delayRespond)
	{
		XSendEvent(xfc->display, xevent->xselectionrequest.requestor, 0, 0, respond);
		XFlush(xfc->display);
		free(respond);
	}

	return TRUE;
}

static BOOL xf_cliprdr_process_selection_clear(xfClipboard* clipboard,
        XEvent* xevent)
{
	xfContext* xfc = clipboard->xfc;

	if (xf_cliprdr_is_self_owned(clipboard))
		return FALSE;

	XDeleteProperty(xfc->display, clipboard->root_window, clipboard->property_atom);
	return TRUE;
}

static BOOL xf_cliprdr_process_property_notify(xfClipboard* clipboard,
        XEvent* xevent)
{
	xfCliprdrFormat* format;
	xfContext* xfc = clipboard->xfc;

	if (!clipboard)
		return TRUE;

	if (xevent->xproperty.atom != clipboard->property_atom)
		return FALSE; /* Not cliprdr-related */

	if (xevent->xproperty.window == clipboard->root_window)
	{
		xf_cliprdr_send_client_format_list(clipboard);
	}
	else if ((xevent->xproperty.window == xfc->drawable) &&
	         (xevent->xproperty.state == PropertyNewValue) && clipboard->incr_starts)
	{
		format = xf_cliprdr_get_client_format_by_id(clipboard,
		         clipboard->requestedFormatId);

		if (format)
			xf_cliprdr_get_requested_data(clipboard, format->atom);
	}

	return TRUE;
}

void xf_cliprdr_handle_xevent(xfContext* xfc, XEvent* event)
{
	xfClipboard* clipboard;

	if (!xfc || !event)
		return;

	clipboard = xfc->clipboard;

	if (!clipboard)
		return;

#ifdef WITH_XFIXES

	if (clipboard->xfixes_supported
	    && event->type == XFixesSelectionNotify + clipboard->xfixes_event_base)
	{
		XFixesSelectionNotifyEvent* se = (XFixesSelectionNotifyEvent*) event;

		if (se->subtype == XFixesSetSelectionOwnerNotify)
		{
			if (se->selection != clipboard->clipboard_atom)
				return;

			if (XGetSelectionOwner(xfc->display, se->selection) == xfc->drawable)
				return;

			clipboard->owner = None;
			xf_cliprdr_check_owner(clipboard);
		}

		return;
	}

#endif

	switch (event->type)
	{
		case SelectionNotify:
			xf_cliprdr_process_selection_notify(clipboard, event);
			break;

		case SelectionRequest:
			xf_cliprdr_process_selection_request(clipboard, event);
			break;

		case SelectionClear:
			xf_cliprdr_process_selection_clear(clipboard, event);
			break;

		case PropertyNotify:
			xf_cliprdr_process_property_notify(clipboard, event);
			break;

		case FocusIn:
			if (!clipboard->xfixes_supported)
			{
				xf_cliprdr_check_owner(clipboard);
			}

			break;
	}
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
UINT xf_cliprdr_send_client_capabilities(xfClipboard* clipboard)
{
	CLIPRDR_CAPABILITIES capabilities;
	CLIPRDR_GENERAL_CAPABILITY_SET generalCapabilitySet;
	capabilities.cCapabilitiesSets = 1;
	capabilities.capabilitySets = (CLIPRDR_CAPABILITY_SET*) &
	                              (generalCapabilitySet);
	generalCapabilitySet.capabilitySetType = CB_CAPSTYPE_GENERAL;
	generalCapabilitySet.capabilitySetLength = 12;
	generalCapabilitySet.version = CB_CAPS_VERSION_2;
	generalCapabilitySet.generalFlags = CB_USE_LONG_FORMAT_NAMES;
	return clipboard->context->ClientCapabilities(clipboard->context,
	        &capabilities);
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
UINT xf_cliprdr_send_client_format_list(xfClipboard* clipboard)
{
	UINT32 i, numFormats;
	CLIPRDR_FORMAT* formats = NULL;
	CLIPRDR_FORMAT_LIST formatList;
	xfContext* xfc = clipboard->xfc;
	UINT ret;
	ZeroMemory(&formatList, sizeof(CLIPRDR_FORMAT_LIST));
	numFormats = clipboard->numClientFormats;

	if (numFormats)
	{
		if (!(formats = (CLIPRDR_FORMAT*) calloc(numFormats, sizeof(CLIPRDR_FORMAT))))
		{
			WLog_ERR(TAG, "failed to allocate %d CLIPRDR_FORMAT structs", numFormats);
			return CHANNEL_RC_NO_MEMORY;
		}
	}

	for (i = 0; i < numFormats; i++)
	{
		formats[i].formatId = clipboard->clientFormats[i].formatId;
		formats[i].formatName = clipboard->clientFormats[i].formatName;
	}

	formatList.msgFlags = CB_RESPONSE_OK;
	formatList.numFormats = numFormats;
	formatList.formats = formats;
	ret = clipboard->context->ClientFormatList(clipboard->context, &formatList);
	free(formats);

	if (clipboard->owner && clipboard->owner != xfc->drawable)
	{
		/* Request the owner for TARGETS, and wait for SelectionNotify event */
		XConvertSelection(xfc->display, clipboard->clipboard_atom,
		                  clipboard->targets[1], clipboard->property_atom, xfc->drawable, CurrentTime);
	}

	return ret;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
UINT xf_cliprdr_send_client_format_list_response(xfClipboard* clipboard,
        BOOL status)
{
	CLIPRDR_FORMAT_LIST_RESPONSE formatListResponse;
	formatListResponse.msgType = CB_FORMAT_LIST_RESPONSE;
	formatListResponse.msgFlags = status ? CB_RESPONSE_OK : CB_RESPONSE_FAIL;
	formatListResponse.dataLen = 0;
	return clipboard->context->ClientFormatListResponse(clipboard->context,
	        &formatListResponse);
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT xf_cliprdr_monitor_ready(CliprdrClientContext* context,
                                     CLIPRDR_MONITOR_READY* monitorReady)
{
	xfClipboard* clipboard = (xfClipboard*) context->custom;
	UINT ret;

	if ((ret = xf_cliprdr_send_client_capabilities(clipboard)) != CHANNEL_RC_OK)
		return ret;

	if ((ret = xf_cliprdr_send_client_format_list(clipboard)) != CHANNEL_RC_OK)
		return ret;

	clipboard->sync = TRUE;
	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT xf_cliprdr_server_capabilities(CliprdrClientContext* context,
        CLIPRDR_CAPABILITIES* capabilities)
{
	//xfClipboard* clipboard = (xfClipboard*) context->custom;
	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT xf_cliprdr_server_format_list(CliprdrClientContext* context,
        CLIPRDR_FORMAT_LIST* formatList)
{
	int i, j;
	CLIPRDR_FORMAT* format;
	xfClipboard* clipboard = (xfClipboard*) context->custom;
	xfContext* xfc = clipboard->xfc;
	UINT ret;
	BOOL Moxel = FALSE;

	if (clipboard->data)
	{
		free(clipboard->data);
		clipboard->data = NULL;
	}

	clipboard->data_format_id = -1;
	clipboard->data_format_name = NULL;

	if (clipboard->serverFormats)
	{
		for (i = 0; i < clipboard->numServerFormats; i++)
			free(clipboard->serverFormats[i].formatName);

		free(clipboard->serverFormats);
		clipboard->serverFormats = NULL;
		clipboard->numServerFormats = 0;
	}

	clipboard->numServerFormats = formatList->numFormats + 1; /* +1 for CF_RAW */
    for (i = 0; i < formatList->numFormats; i++) // find moxel
	{
		format = &formatList->formats[i];
		if (format->formatName)
		{
			if (strcmp(format->formatName, "1C:Moxcel Docume") == 0) {
				Moxel=TRUE;
				clipboard->numServerFormats = formatList->numFormats + 2;
			}
		}
	}
	
	if (!(clipboard->serverFormats = (CLIPRDR_FORMAT*) calloc(
	                                     clipboard->numServerFormats, sizeof(CLIPRDR_FORMAT))))
	{
		WLog_ERR(TAG, "failed to allocate %d CLIPRDR_FORMAT structs",
		         clipboard->numServerFormats);
		return CHANNEL_RC_NO_MEMORY;
	}

	for (i = 0; i < formatList->numFormats; i++)
	{
		format = &formatList->formats[i];
		clipboard->serverFormats[i].formatId = format->formatId;

		if (format->formatName)
		{
			clipboard->serverFormats[i].formatName = _strdup(format->formatName);

			if (!clipboard->serverFormats[i].formatName)
			{
				for (--i; i >= 0; --i)
					free(clipboard->serverFormats[i].formatName);

				clipboard->numServerFormats = 0;
				free(clipboard->serverFormats);
				clipboard->serverFormats = NULL;
				return CHANNEL_RC_NO_MEMORY;
			}
		}
	}

	/* CF_RAW is always implicitly supported by the server */
	if (Moxel) {
		format = &clipboard->serverFormats[formatList->numFormats]; // add moxel capabilities
		format->formatId = CF_UNICODETEXT;
		format->formatName = NULL;
		format = &clipboard->serverFormats[formatList->numFormats+1];
		format->formatId = CF_RAW;
		format->formatName = NULL;
	} else {
	    format = &clipboard->serverFormats[formatList->numFormats];
	    format->formatId = CF_RAW;
	    format->formatName = NULL;
	}
	xf_cliprdr_provide_server_format_list(clipboard);
	clipboard->numTargets = 2;

	for (i = 0; i < clipboard->numServerFormats-1; i++)
	{
		format = &clipboard->serverFormats[i];

		for (j = 0; j < clipboard->numClientFormats; j++)
		{
			if (xf_cliprdr_formats_equal(format, &clipboard->clientFormats[j]))
			{
				xf_cliprdr_append_target(clipboard, clipboard->clientFormats[j].atom);
			}
		}
	}

	/*for (i = 0; i < formatList->numFormats; i++)
	{
		format = &formatList->formats[i];

		for (j = 0; j < clipboard->numClientFormats; j++)
		{
			if (xf_cliprdr_formats_equal(format, &clipboard->clientFormats[j]))
			{
				xf_cliprdr_append_target(clipboard, clipboard->clientFormats[j].atom);
			}
		}
	}*/

	ret = xf_cliprdr_send_client_format_list_response(clipboard, TRUE);

	XSetSelectionOwner(xfc->display, clipboard->clipboard_atom, xfc->drawable, CurrentTime);

	XFlush(xfc->display);

	return ret;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT xf_cliprdr_server_format_list_response(CliprdrClientContext*
        context, CLIPRDR_FORMAT_LIST_RESPONSE* formatListResponse)
{
	//xfClipboard* clipboard = (xfClipboard*) context->custom;
	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT xf_cliprdr_server_format_data_request(CliprdrClientContext* context,
        CLIPRDR_FORMAT_DATA_REQUEST* formatDataRequest)
{
	BOOL rawTransfer;
	xfCliprdrFormat* format = NULL;
	UINT32 formatId = formatDataRequest->requestedFormatId;
	xfClipboard* clipboard = (xfClipboard*) context->custom;
	xfContext* xfc = clipboard->xfc;
	
	if (formatId==1) {
		clipboard->need_cp1251=TRUE;
		formatId=13;
	} else {
		clipboard->need_cp1251=FALSE;
	}

	
	rawTransfer = xf_cliprdr_is_raw_transfer_available(clipboard);

	if (rawTransfer)
	{
		format = xf_cliprdr_get_client_format_by_id(clipboard, CF_RAW);
		XChangeProperty(xfc->display, xfc->drawable, clipboard->property_atom,
		                XA_INTEGER, 32, PropModeReplace, (BYTE*) &formatId, 1);
	}
	else
		format = xf_cliprdr_get_client_format_by_id(clipboard, formatId);

	if (!format)
		return xf_cliprdr_send_data_response(clipboard, NULL, 0);

	clipboard->requestedFormatId = rawTransfer ? CF_RAW : formatId;
	XConvertSelection(xfc->display, clipboard->clipboard_atom,
	                  format->atom, clipboard->property_atom, xfc->drawable, CurrentTime);
	XFlush(xfc->display);
	/* After this point, we expect a SelectionNotify event from the clipboard owner. */
	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT xf_cliprdr_server_format_data_response(CliprdrClientContext*
        context, CLIPRDR_FORMAT_DATA_RESPONSE* formatDataResponse)
{
	BOOL bSuccess;
	BYTE* pSrcData;
	BYTE* pDstData;
	UINT32 DstSize;
	UINT32 SrcSize;
	UINT32 srcFormatId;
	UINT32 dstFormatId;
	BOOL nullTerminated = FALSE;
	UINT32 size = formatDataResponse->dataLen;
	BYTE* data = formatDataResponse->requestedFormatData;
	xfClipboard* clipboard = (xfClipboard*) context->custom;
	xfContext* xfc = clipboard->xfc;
	// Moxel capabilities
	BOOL Moxel = FALSE;
	UINT32 formatCount;
	UINT32 i;


	if (!clipboard->respond)
		return CHANNEL_RC_OK;

	if (clipboard->data)
	{
		free(clipboard->data);
		clipboard->data = NULL;
	}
	
	// check this is moxel ?
	formatCount = (clipboard->numServerFormats > 0) ? clipboard->numServerFormats - 1 : 0; 
	for (i = 0; i < formatCount; i++)
	{
		CLIPRDR_FORMAT* format = &clipboard->serverFormats[i];
		if (format->formatName)
		{
			if (strcmp(format->formatName, "1C:Moxcel Docume") == 0) {
			    Moxel = TRUE;
			    //WLog_ERR(TAG, "output moxcel - detected");
			}
		}
	}


	pDstData = NULL;
	DstSize = 0;
	srcFormatId = 0;
	dstFormatId = 0;

	if (clipboard->data_raw_format)
	{
		srcFormatId = CF_RAW;
		dstFormatId = CF_RAW;
	}
	else if (clipboard->data_format_name)
	{
		if (strcmp(clipboard->data_format_name, "HTML Format") == 0)
		{
			srcFormatId = ClipboardGetFormatId(clipboard->system, "HTML Format");
			dstFormatId = ClipboardGetFormatId(clipboard->system, "text/html");
			nullTerminated = TRUE;
		}
	}
	else
	{
		switch (clipboard->data_format_id)
		{
			case CF_TEXT:
				srcFormatId = CF_TEXT;
				dstFormatId = ClipboardGetFormatId(clipboard->system, "UTF8_STRING");
				nullTerminated = TRUE;
				break;

			case CF_OEMTEXT:
				srcFormatId = CF_OEMTEXT;
				dstFormatId = ClipboardGetFormatId(clipboard->system, "UTF8_STRING");
				nullTerminated = TRUE;
				break;

			case CF_UNICODETEXT:
				srcFormatId = CF_UNICODETEXT;
				dstFormatId = ClipboardGetFormatId(clipboard->system, "UTF8_STRING");
				nullTerminated = TRUE;
				if (Moxel) {
				    //WLog_ERR(TAG, "before size %d",size);
				    size = 0;
				    while ((data[size] != '\0')||(data[size+1] != '\0')) size++;
				    size++;
				    //WLog_ERR(TAG, "after size %d",size);
			    }
				break;

			case CF_DIB:
				srcFormatId = CF_DIB;
				dstFormatId = ClipboardGetFormatId(clipboard->system, "image/bmp");
				break;
		}
	}

	SrcSize = (UINT32) size;
	pSrcData = (BYTE*) malloc(SrcSize);

	if (!pSrcData)
		return CHANNEL_RC_NO_MEMORY;

	CopyMemory(pSrcData, data, SrcSize);

//	winpr_HexDump(TAG, WLOG_ERROR, pSrcData, SrcSize);

	bSuccess = ClipboardSetData(clipboard->system, srcFormatId, (void*) pSrcData, SrcSize);

	if (!bSuccess)
		free (pSrcData);

	if (bSuccess)
	{
		DstSize = 0;
		pDstData = (BYTE*) ClipboardGetData(clipboard->system, dstFormatId, &DstSize);

		if (nullTerminated)
		{
			while (DstSize > 0 && pDstData[DstSize - 1] == '\0')
				DstSize--;
		}
	}

	clipboard->data = pDstData;
	clipboard->data_length = DstSize;
	xf_cliprdr_provide_data(clipboard, clipboard->respond, pDstData, DstSize);
	XSendEvent(xfc->display, clipboard->respond->xselection.requestor, 0, 0,
	           clipboard->respond);
	XFlush(xfc->display);
	free(clipboard->respond);
	clipboard->respond = NULL;
	return CHANNEL_RC_OK;
}

xfClipboard* xf_clipboard_new(xfContext* xfc)
{
	int n;
	rdpChannels* channels;
	xfClipboard* clipboard;

	if (!(clipboard = (xfClipboard*) calloc(1, sizeof(xfClipboard))))
	{
		WLog_ERR(TAG, "failed to allocate xfClipboard data");
		return NULL;
	}

	xfc->clipboard = clipboard;
	clipboard->xfc = xfc;
	channels = ((rdpContext*) xfc)->channels;
	clipboard->channels = channels;
	clipboard->system = ClipboardCreate();
	clipboard->requestedFormatId = -1;
	clipboard->root_window = DefaultRootWindow(xfc->display);
	clipboard->clipboard_atom = XInternAtom(xfc->display, "CLIPBOARD", FALSE);

	if (clipboard->clipboard_atom == None)
	{
		WLog_ERR(TAG, "unable to get CLIPBOARD atom");
		free(clipboard);
		return NULL;
	}

	clipboard->property_atom = XInternAtom(xfc->display, "_FREERDP_CLIPRDR", FALSE);
	clipboard->raw_transfer_atom = XInternAtom(xfc->display, "_FREERDP_CLIPRDR_RAW",
	                               FALSE);
	clipboard->raw_format_list_atom = XInternAtom(xfc->display,
	                                  "_FREERDP_CLIPRDR_FORMATS", FALSE);
	xf_cliprdr_set_raw_transfer_enabled(clipboard, TRUE);
	XSelectInput(xfc->display, clipboard->root_window, PropertyChangeMask);
#ifdef WITH_XFIXES

	if (XFixesQueryExtension(xfc->display, &clipboard->xfixes_event_base,
	                         &clipboard->xfixes_error_base))
	{
		int xfmajor, xfminor;

		if (XFixesQueryVersion(xfc->display, &xfmajor, &xfminor))
		{
			XFixesSelectSelectionInput(xfc->display, clipboard->root_window,
			                           clipboard->clipboard_atom, XFixesSetSelectionOwnerNotifyMask);
			clipboard->xfixes_supported = TRUE;
		}
		else
		{
			WLog_ERR(TAG, "Error querying X Fixes extension version");
		}
	}
	else
	{
		WLog_ERR(TAG, "Error loading X Fixes extension");
	}

#else
	WLog_ERR(TAG,
	         "Warning: Using clipboard redirection without XFIXES extension is strongly discouraged!");
#endif
	n = 0;
	clipboard->clientFormats[n].atom = XInternAtom(xfc->display, "_FREERDP_RAW",
	                                   False);
	clipboard->clientFormats[n].formatId = CF_RAW;
	n++;
	clipboard->clientFormats[n].atom = XInternAtom(xfc->display, "UTF8_STRING",
	                                   False);
	clipboard->clientFormats[n].formatId = CF_UNICODETEXT;
	n++;
	clipboard->clientFormats[n].atom = XA_STRING;
	clipboard->clientFormats[n].formatId = CF_TEXT;
	n++;
	clipboard->clientFormats[n].atom = XInternAtom(xfc->display, "image/png",
	                                   False);
	clipboard->clientFormats[n].formatId = CB_FORMAT_PNG;
	n++;
	clipboard->clientFormats[n].atom = XInternAtom(xfc->display, "image/jpeg",
	                                   False);
	clipboard->clientFormats[n].formatId = CB_FORMAT_JPEG;
	n++;
	clipboard->clientFormats[n].atom = XInternAtom(xfc->display, "image/gif",
	                                   False);
	clipboard->clientFormats[n].formatId = CB_FORMAT_GIF;
	n++;
	clipboard->clientFormats[n].atom = XInternAtom(xfc->display, "image/bmp",
	                                   False);
	clipboard->clientFormats[n].formatId = CF_DIB;
	n++;
	clipboard->clientFormats[n].atom = XInternAtom(xfc->display, "text/html",
	                                   False);
	clipboard->clientFormats[n].formatId = CB_FORMAT_HTML;
	clipboard->clientFormats[n].formatName = _strdup("HTML Format");

	if (!clipboard->clientFormats[n].formatName)
	{
		ClipboardDestroy(clipboard->system);
		free(clipboard);
		return NULL;
	}

	n++;
	clipboard->numClientFormats = n;
	clipboard->targets[0] = XInternAtom(xfc->display, "TIMESTAMP", FALSE);
	clipboard->targets[1] = XInternAtom(xfc->display, "TARGETS", FALSE);
	clipboard->numTargets = 2;
	clipboard->incr_atom = XInternAtom(xfc->display, "INCR", FALSE);
	return clipboard;
}

void xf_clipboard_free(xfClipboard* clipboard)
{
	int i;

	if (!clipboard)
		return;

	if (clipboard->serverFormats)
	{
		for (i = 0; i < clipboard->numServerFormats; i++)
			free(clipboard->serverFormats[i].formatName);

		free(clipboard->serverFormats);
		clipboard->serverFormats = NULL;
	}

	if (clipboard->numClientFormats)
	{
		for (i = 0; i < clipboard->numClientFormats; i++)
			free(clipboard->clientFormats[i].formatName);
	}

	ClipboardDestroy(clipboard->system);
	free(clipboard->data);
	free(clipboard->respond);
	free(clipboard->incr_data);
	free(clipboard);
}

void xf_cliprdr_init(xfContext* xfc, CliprdrClientContext* cliprdr)
{
	xfc->cliprdr = cliprdr;
	xfc->clipboard->context = cliprdr;
	cliprdr->custom = (void*) xfc->clipboard;
	cliprdr->MonitorReady = xf_cliprdr_monitor_ready;
	cliprdr->ServerCapabilities = xf_cliprdr_server_capabilities;
	cliprdr->ServerFormatList = xf_cliprdr_server_format_list;
	cliprdr->ServerFormatListResponse = xf_cliprdr_server_format_list_response;
	cliprdr->ServerFormatDataRequest = xf_cliprdr_server_format_data_request;
	cliprdr->ServerFormatDataResponse = xf_cliprdr_server_format_data_response;
}

void xf_cliprdr_uninit(xfContext* xfc, CliprdrClientContext* cliprdr)
{
	xfc->cliprdr = NULL;
	cliprdr->custom = NULL;

	if (xfc->clipboard)
		xfc->clipboard->context = NULL;
}
