/*
*  Copyright (C) 2016  <maxpat78> <https://github.com/maxpat78>
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License along
*  with this program; if not, write to the Free Software Foundation, Inc.,
*  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

//
//	CryptoPad - simple text editor application supporting ZIP AE-1 encryption
//
#include <tchar.h>
#include <windows.h>
#include <shlwapi.h>
#include <commctrl.h>

#include "mZipAES.h"
#include "resource.h"

#define APP_TITLE   _T("CryptoPad")

enum Encodings {
	ENC_UNKNOWN,
	ENC_ANSI,
	ENC_UTF8,
	ENC_UTF8_BOM,
	ENC_UTF16LE,
	ENC_UTF16BE
};

enum Eol_Markers
{
	EOL_NONE,   // None
	EOL_CR,		// Mac
	EOL_LF,		// Unix
	EOL_CRLF,	// DOS
	EOL_MIXED	// Unbalanced (to be fixed)
};

// Scans a NULL terminated TCHAR buffer and determines the line ending 
int DetectEOL(TCHAR* Buf, UINT* cCR, UINT* cLF, UINT* cCRLF)
{
	TCHAR* p = Buf;
	TCHAR* q = NULL;
	UINT cr = 0, lf = 0, crlf = 0;

	while (*p)
	{
		if (*p == _T('\r'))
		{
			cr++;
			q = p;
		}
		else if (*p == _T('\n'))
		{
			lf++;
			if (q + 1 == p)
			{
				crlf++;
				cr--;
				lf--;
			}
		}
		p++;
	}

	*cCR = cr;
	*cLF = lf;
	*cCRLF = crlf;

	if (!cr && !lf && !crlf)
		return EOL_NONE;
	else if (!cr && !lf)
		return EOL_CRLF;
	else if (!lf && !crlf)
		return EOL_CR;
	else if (!cr && !crlf)
		return EOL_LF;
	else
		return EOL_MIXED;
}

// Converts EOL characters in a NULL-terminated TCHAR buffer,
// copying the result in a user allocated buffer. If uiDstSize
// or DstBuf is NULL, returns the required buffer size.
int ConvertEOL(
	TCHAR* SrcBuf, UINT uiSrcSize, UINT uiSrcEol,
	TCHAR* DstBuf, UINT uiDstSize, UINT uiDstEol,
	UINT cCR, UINT cLF, UINT cCRLF)
{
	UINT uiSize = uiSrcSize;
	TCHAR *p, *q=NULL;

	if (uiSrcEol == uiDstEol)
		return -1;

	if (uiDstEol != EOL_CR && uiDstEol != EOL_LF && uiDstEol != EOL_CRLF)
		return -1;

	if (uiDstEol == EOL_CRLF)
		if (uiSrcEol == EOL_LF)
			uiSize += (cLF * sizeof(TCHAR));
		else if (uiSrcEol == EOL_CR)
			uiSize += (cCR * sizeof(TCHAR));
		else
			uiSize += (sizeof(TCHAR) * (cCR+cLF));
	else
		uiSize -= ((cCRLF/2) * sizeof(TCHAR));

	if (!uiDstSize || !DstBuf)
		return uiSize;

	if (uiDstSize < uiSize)
		return -1;

	p = DstBuf;

	while (*SrcBuf)
	{
		if (*SrcBuf == _T('\r'))
			if (uiDstEol == EOL_CRLF)
			{
				*p++ = _T('\r');
				*p++ = _T('\n');
				q = SrcBuf;
			}
			else // EOL_LF
			{
				if (uiDstEol == EOL_LF)
					*p++ = _T('\n');
				else
					*p++ = *SrcBuf;
			}
		else if (*SrcBuf == _T('\n'))
			if (uiDstEol == EOL_CRLF)
			{
				if (q + 1 != SrcBuf)
				{
					*p++ = _T('\r');
					*p++ = _T('\n');
				}
			}
			else // EOL_CR
			{
				if (uiSrcEol != EOL_CRLF)
					*p++ = _T('\r');
			}
		else // copy normal TCHAR
			*p++ = *SrcBuf;
		SrcBuf++;
	}

	*p = _T('\0');

	return 0;
}


// Global variables
TCHAR		szAppName[] = APP_TITLE;
HWND		hwndMain = NULL;
HWND		hwndEdit;

TCHAR szFileName[MAX_PATH];
TCHAR szFileTitle[_MAX_FNAME + _MAX_EXT];
TCHAR s0[512], s1[512];
TCHAR *szEditBuffer, *szEditBufferBase;
UINT uiFileEncoding = ENC_UTF8_BOM; // Default output encoding
UINT uiFileEOL = EOL_CRLF; // Default output line ending
char* document_password; // NULL ended ASCII password


LPVOID Malloc(SIZE_T dwBytes)
{
	LPVOID p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytes);

	if (! p)
	{
		LoadString(GetModuleHandle(0), IDS_ENOMEM, &s0, sizeof(s0) / sizeof(TCHAR));
		LoadString(GetModuleHandle(0), IDS_ERROR, &s1, sizeof(s1) / sizeof(TCHAR));
		MessageBox(hwndMain, s0, s1, MB_OK | MB_ICONSTOP);
		return NULL;
	}

	return p;
}

BOOL Free(LPVOID lpMem)
{
	return HeapFree(GetProcessHeap(), 0, lpMem);
}


void FlushMenus()
{
	HMENU menu;
	LONG gsel, flag;

	menu = GetMenu(hwndMain); // menu bar
	CheckMenuItem(menu, ID_ENCODING_CR, (uiFileEOL == EOL_CR) ? MF_CHECKED : MF_UNCHECKED);
	CheckMenuItem(menu, ID_ENCODING_LF, (uiFileEOL == EOL_LF) ? MF_CHECKED : MF_UNCHECKED);
	CheckMenuItem(menu, ID_ENCODING_CRLF, (uiFileEOL == EOL_CRLF) ? MF_CHECKED : MF_UNCHECKED);

	CheckMenuItem(menu, ID_ENCODING_ASCII, (uiFileEncoding == ENC_ANSI) ? MF_CHECKED : MF_UNCHECKED);
	CheckMenuItem(menu, ID_ENCODING_UTF8BOM, (uiFileEncoding == ENC_UTF8_BOM || uiFileEncoding == ENC_UTF8) ? MF_CHECKED : MF_UNCHECKED);
	CheckMenuItem(menu, ID_ENCODING_UTF16LE, (uiFileEncoding == ENC_UTF16LE) ? MF_CHECKED : MF_UNCHECKED);
	CheckMenuItem(menu, ID_ENCODING_UTF16BE, (uiFileEncoding == ENC_UTF16BE) ? MF_CHECKED : MF_UNCHECKED);

	EnableMenuItem(menu, ID_FILE_RESETPASSWORD, (document_password && document_password[0]) ? MF_ENABLED : MF_GRAYED);
	EnableMenuItem(menu, IDM_EDUNDO, (SendMessage(hwndEdit, EM_CANUNDO, 0, 0)) ? MF_ENABLED : MF_GRAYED);
	gsel = SendMessage(hwndEdit, EM_GETSEL, 0, 0);
	flag = LOWORD(gsel) == HIWORD(gsel) ? MF_GRAYED : MF_ENABLED;
	EnableMenuItem(menu, IDM_EDCUT, flag);
	EnableMenuItem(menu, IDM_EDCOPY, flag);
	EnableMenuItem(menu, IDM_EDDEL, flag);

	gsel = GetMenuState(menu, IDM_EDALLSEL, MF_BYCOMMAND);
	if ((gsel == MF_GRAYED) && (flag == MF_GRAYED))
	{
		EnableMenuItem(menu, IDM_EDALLSEL, MF_ENABLED);
	}

	if (OpenClipboard(hwndEdit))
	{
		gsel = IsClipboardFormatAvailable(CF_TEXT);
		CloseClipboard();
	}
	EnableMenuItem(menu, IDM_EDPASTE, gsel ? MF_ENABLED : MF_GRAYED);
}


BOOL LoadFile()
{
	DWORD dwInSize, dwOutSize, dwRead, dwEncoding = ENC_UNKNOWN;
	UINT cCR, cLF, cCRLF;
	char *lpBuffer, *dst;
	LPTSTR p = NULL;
	HANDLE hFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		LoadString(GetModuleHandle(0), IDS_EOPFILE, &s0, sizeof(s0) / sizeof(TCHAR));
		LoadString(GetModuleHandle(0), IDS_ERROR, &s1, sizeof(s1) / sizeof(TCHAR));
		MessageBox(hwndEdit, s0, s1, MB_OK | MB_ICONSTOP);
		return FALSE;
	}

	dwInSize = GetFileSize(hFile, NULL);
	lpBuffer = Malloc(dwInSize + sizeof(TCHAR));
	if (!lpBuffer)
		return FALSE;

	ReadFile(hFile, lpBuffer, dwInSize, &dwRead, 0);
	CloseHandle(hFile);
	if (dwRead != dwInSize)
	{
		LoadString(GetModuleHandle(0), IDS_ERDFILE, &s0, sizeof(s0) / sizeof(TCHAR));
		LoadString(GetModuleHandle(0), IDS_ERROR, &s1, sizeof(s1) / sizeof(TCHAR));
		MessageBox(hwndEdit, s0, s1, MB_OK | MB_ICONSTOP);
		return FALSE;
	}

	if (dwInSize > 4 && *((DWORD*)lpBuffer) == 0x04034B50)
	{
		// Try to open a special ZIP document
		dwRead = 0;
		dwOutSize = 0;
		dwRead = MiniZipAE1Read(lpBuffer, dwInSize, &dst, (unsigned long*)&dwOutSize, document_password);

		if (dwRead == MZAE_ERR_SUCCESS)
		{
			dst = Malloc(dwOutSize+sizeof(TCHAR));
			if (!dst)
				return FALSE;
		}

		dwRead = MiniZipAE1Read(lpBuffer, dwInSize, &dst, (unsigned long*)&dwOutSize, document_password);
		
		if (dwRead == MZAE_ERR_SUCCESS)
		{
			dwEncoding = ENC_UTF8; // Text format is always UTF-8
			Free(lpBuffer);
			p = lpBuffer = dst;
		}
		else if (dwRead == MZAE_ERR_BADVV)
		{
			Free(dst);
			LoadString(GetModuleHandle(0), IDS_EBADPW, &s0, sizeof(s0) / sizeof(TCHAR));
			LoadString(GetModuleHandle(0), IDS_ERROR, &s1, sizeof(s1) / sizeof(TCHAR));
			MessageBox(hwndEdit, s0, s1, MB_OK | MB_ICONSTOP);
			return FALSE;
		}
		else if (dwRead == MZAE_ERR_NOPW)
		{
			Free(dst);
			PostMessage(hwndMain, WM_COMMAND, IDM_FILE_PASSWORD, TRUE);
			return FALSE;
		}
		else if (dwRead != MZAE_ERR_BADZIP)
		{
			// Problem with the decoder
			Free(dst);
			LoadString(GetModuleHandle(0), IDS_EDCRYPT, &s0, sizeof(s0) / sizeof(TCHAR));
			LoadString(GetModuleHandle(0), IDS_ERROR, &s1, sizeof(s1) / sizeof(TCHAR));
			MessageBox(hwndEdit, s0, s1, MB_OK | MB_ICONSTOP);
			return FALSE;
		}
	}

	// If plain text document loaded
	// dwInSize will represent the NULL terminated buffer length
	if (dwEncoding == ENC_UNKNOWN)
	{
		if (dwInSize >= 2 && lpBuffer[0] == (char)0xFF && lpBuffer[1] == (char)0xFE)
		{
			dwEncoding = ENC_UTF16LE;
			dwInSize = dwInSize - 2 + sizeof(TCHAR);
			p = lpBuffer;
			p++;
		}
		else if (dwInSize >= 2 && lpBuffer[0] == (char)0xFE && lpBuffer[1] == (char)0xFF)
		{
			dwEncoding = ENC_UTF16BE;
			dwInSize = dwInSize - 2 + sizeof(TCHAR);
			p = lpBuffer;
			p++;

			#define BS16(x) ((short)x & 0xFF00) >> 8 | ((short)x & 0xFF) << 8

			TCHAR* t = p;
			// Swap bytes in place until final NULL
			while (*t)
			{
				*t = BS16(*t);
				t++;
			}
		}
		else if (dwInSize >= 3 && lpBuffer[0] == (char)0xEF && lpBuffer[1] == (char)0xBB && lpBuffer[2] == (char)0xBF)
		{
			dwEncoding = ENC_UTF8_BOM;
			dwInSize = dwInSize - 3 + sizeof(char);
			p = lpBuffer + 3;
		}
		else
		{
			dwEncoding = ENC_ANSI;
			dwInSize = dwInSize + sizeof(char);
			p = lpBuffer;
		}
	}

	if (dwEncoding == ENC_ANSI || dwEncoding == ENC_UTF8 || dwEncoding == ENC_UTF8_BOM)
	{
		// CHARACTERS representing the NULL terminated target string
		int cchSize = MultiByteToWideChar(dwEncoding == ENC_ANSI? CP_ACP:CP_UTF8, 0, p, -1, 0, 0);
		dwInSize = cchSize * sizeof(TCHAR);
		szEditBuffer = Malloc(dwInSize);
		MultiByteToWideChar(dwEncoding == ENC_ANSI ? CP_ACP : CP_UTF8, 0, p, -1, szEditBuffer, cchSize * sizeof(TCHAR));
		Free(lpBuffer);
		lpBuffer = szEditBuffer;
	}
	else
		szEditBuffer = p;

	// Records the original file encoding
	uiFileEncoding = dwEncoding;

	// Records the original file EOL and converts it to CR-LF
	uiFileEOL = DetectEOL(szEditBuffer, &cCR, &cLF, &cCRLF);

	if (uiFileEOL != EOL_CRLF && uiFileEOL != EOL_NONE)
	{
		int cb = ConvertEOL(szEditBuffer, dwInSize,
			uiFileEOL, NULL, 0, EOL_CRLF,
			cCR, cLF, cCRLF);
		TCHAR* q = Malloc(cb);
		cb = ConvertEOL(szEditBuffer, dwInSize,
			uiFileEOL, q, cb, EOL_CRLF,
			cCR, cLF, cCRLF);
		szEditBuffer = q;
		Free(lpBuffer);
		lpBuffer = q;
	}

	// Assign a valid default line ending
	if (uiFileEOL == EOL_NONE)
		uiFileEOL = EOL_CRLF;

	if (uiFileEOL == EOL_MIXED)
	{
		if (cCR > cLF && cCR > cCRLF)
			uiFileEOL = EOL_CR;
		else if (cLF > cCR && cLF > cCRLF)
			uiFileEOL = EOL_LF;
		else
			uiFileEOL = EOL_CRLF;
	}

	szEditBufferBase = lpBuffer;

	return TRUE;
}



BOOL SaveFile(int size)
{
	char *lpBuffer, *dst;
	DWORD dwSize, err;
	LPTSTR p = NULL;
	HANDLE hFile = CreateFile(szFileName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		LoadString(GetModuleHandle(0), IDS_EWRFILE, &s0, sizeof(s0) / sizeof(TCHAR));
		LoadString(GetModuleHandle(0), IDS_ERROR, &s1, sizeof(s1) / sizeof(TCHAR));
		MessageBox(hwndEdit, s0, s1, MB_OK | MB_ICONSTOP);
		return FALSE;
	}

	if (document_password && document_password[0])
	{
		uiFileEncoding = ENC_UTF8; // An encrypted file becomes ALWAYS UTF8
		uiFileEOL = EOL_CRLF; // And CR-LF line ended! 
	}

	if (uiFileEOL != EOL_CRLF)
	{
		UINT cCR=0, cLF=0, cCRLF=0;
		int cb = ConvertEOL(szEditBuffer, size,
			EOL_CRLF, NULL, 0, uiFileEOL,
			cCR, cLF, cCRLF);
		TCHAR* q = Malloc(cb);
		cb = ConvertEOL(szEditBuffer, size,	EOL_CRLF,
			q, cb, uiFileEOL,
			cCR, cLF, cCRLF);
		szEditBuffer = q;
		Free(szEditBuffer);
	}

	if (uiFileEncoding == ENC_ANSI || uiFileEncoding == ENC_UTF8 || uiFileEncoding == ENC_UTF8_BOM || uiFileEncoding == ENC_UTF8)
	{
		// CHARACTERS representing the NULL terminated target string
		int cchSize = WideCharToMultiByte(uiFileEncoding == ENC_ANSI? CP_ACP:CP_UTF8, 0, szEditBuffer, -1, 0, 0, 0, 0);
		p = Malloc(cchSize * sizeof(char));
		WideCharToMultiByte(uiFileEncoding == ENC_ANSI ? CP_ACP : CP_UTF8, 0, szEditBuffer, -1, p, cchSize, 0, 0);
		size = cchSize - 1; // Does NOT count ending NULL
	}
	else if (uiFileEncoding == ENC_UTF16BE)
	{
		TCHAR* t = szEditBuffer;
		// Swap bytes in place until final NULL
		while (*t)
		{
			*t = BS16(*t);
			t++;
		}
		p = szEditBuffer;
		size--;
	}
	else
	{
		p = szEditBuffer;
		size--;
	}

	if (document_password && document_password[0])
	{
		DWORD dwOutSize = 0;
		err = MiniZipAE1Write(p, size, &dst, (unsigned long*)&dwOutSize, document_password);
		if (err == MZAE_ERR_SUCCESS)
		{
			dst = Malloc(dwOutSize);
			if (!dst)
				return FALSE;
		}
		else goto aeerr;
		err = MiniZipAE1Write(p, size, &dst, (unsigned long*)&dwOutSize, document_password);
		if (err != MZAE_ERR_SUCCESS)
		{
			Free(dst);
aeerr:
			LoadString(GetModuleHandle(0), IDS_EECRYPT, &s0, sizeof(s0) / sizeof(TCHAR));
			LoadString(GetModuleHandle(0), IDS_ERROR, &s1, sizeof(s1) / sizeof(TCHAR));
			MessageBox(hwndEdit, s0, s1, MB_OK | MB_ICONSTOP);
			return FALSE;
		}
		Free(p);
		p = dst;
		size = dwOutSize;
	}

	// Emit preamble if necessary
	if (uiFileEncoding == ENC_UTF16LE)
		err = WriteFile(hFile, "\xFF\xFE", 2, &dwSize, 0);
	else if (uiFileEncoding == ENC_UTF16BE)
		err = WriteFile(hFile, "\xFE\xFF", 2, &dwSize, 0);
	else if (uiFileEncoding == ENC_UTF8_BOM)
		err = WriteFile(hFile, "\xEF\xBB\xBF", 3, &dwSize, 0);

	err += WriteFile(hFile, p, size, &size, 0);

	if (! err)
	{
		LoadString(GetModuleHandle(0), IDS_EWRFILE, &s0, sizeof(s0) / sizeof(TCHAR));
		LoadString(GetModuleHandle(0), IDS_ERROR, &s1, sizeof(s1) / sizeof(TCHAR));
		MessageBox(hwndEdit, s0, s1, MB_OK | MB_ICONSTOP);
		return FALSE;
	}

	CloseHandle(hFile);
	
	return TRUE;
}


BOOL ShowSaveAsFileDlg(HWND hwnd, PSTR pstrFileName, PSTR pstrTitleName)
{
	DWORD ret;
	TCHAR* p;
	OPENFILENAME ofn;
	ZeroMemory(&ofn, sizeof(ofn));

	LoadString(GetModuleHandle(0), IDS_FILTER, &s0, sizeof(s0) / sizeof(TCHAR));
	p = s0;
	while(*p)
	{
		if (*p == _T('\1'))
			*p = _T('\0');
		p++;
	}

	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hwnd;
	ofn.lpstrFilter = s0;
	ofn.lpstrFile = pstrFileName;
	ofn.lpstrFileTitle = pstrTitleName;

	ofn.nFilterIndex = 1;
	ofn.nMaxFile = MAX_PATH;
	ofn.nMaxFileTitle = _MAX_FNAME + _MAX_EXT;

	ofn.Flags = OFN_EXPLORER | OFN_ENABLESIZING;

	ret = GetSaveFileName(&ofn);

	// Add missing extension
	if (!StrRStrI(ofn.lpstrFile, 0, _T(".txt")))
		lstrcat(ofn.lpstrFile, _T(".txt"));

	return ret;
}

BOOL ShowOpenFileDlg(HWND hwnd, PSTR pstrFileName, PSTR pstrTitleName)
{
	DWORD ret;
	TCHAR *p;
	OPENFILENAME ofn;

	ZeroMemory(&ofn, sizeof(ofn));
	LoadString(GetModuleHandle(0), IDS_FILTER, &s1, sizeof(s1) / sizeof(TCHAR));
	p = s1;
	while (*p)
	{
		if (*p == _T('\1'))
			*p = _T('\0');
		p++;
	}

	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner		= hwnd;
	ofn.lpstrFilter		= s1;
	ofn.lpstrFile = pstrFileName;
	ofn.lpstrFileTitle = pstrTitleName;
	ofn.nFilterIndex	= 1;
	ofn.nMaxFile		= MAX_PATH;
	ofn.nMaxFileTitle	= _MAX_FNAME + _MAX_EXT;

	ofn.Flags			=	OFN_ENABLESIZING		|
							OFN_FILEMUSTEXIST		|
							OFN_PATHMUSTEXIST;

	ret = GetOpenFileName(&ofn);

	// Remove extension
	if (StrRStrI(ofn.lpstrFileTitle, 0, _T(".txt")))
		ofn.lpstrFileTitle[lstrlen(ofn.lpstrFileTitle) - 4] = _T('\0');

	return ret;
}

void ShowAboutDlg(HWND hwndParent)
{
    HICON notepadIcon = LoadIcon(GetModuleHandle(0), MAKEINTRESOURCE(IDI_ICON1));

	LoadString(GetModuleHandle(0), IDS_NOTEPAD, s0, sizeof(s0) / sizeof(TCHAR));
	LoadString(GetModuleHandle(0), IDS_NOTEPAD2, s1, sizeof(s1) / sizeof(TCHAR));
	ShellAbout(hwndMain, s0, s1, notepadIcon);
    DeleteObject(notepadIcon);
}

void SetWindowFileName(HWND hwnd, TCHAR *szFileName)
{
	TCHAR ach[MAX_PATH + sizeof(szAppName) + 4];

	wsprintf(ach, _T("%s - %s"), szFileName, szAppName);

	SetWindowText(hwnd, ach);
}

//
//	Main window procedure
//
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static int width, height;
	HFONT hFont;

	switch(msg)
	{
	case WM_CREATE:
		document_password = Malloc(128);
		hwndEdit = CreateWindowEx(0,
		_T("EDIT"), NULL,
		WS_VSCROLL | WS_CHILD | WS_VISIBLE |
		ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL,
		0, 0, 0, 0,
		hwnd,
		0,
		GetModuleHandle(0),
		0);
		hFont = CreateFont(0,0,0,0,FW_DONTCARE,0,0,0,DEFAULT_CHARSET,OUT_OUTLINE_PRECIS,
                CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY, VARIABLE_PITCH,TEXT("Verdana"));
		SendMessage(hwndEdit, WM_SETFONT, (WPARAM) hFont, 1);
		// automatically create new document when we start
		PostMessage(hwnd, WM_COMMAND, IDM_FILE_NEW, 0);
		return 0;

	case WM_CLOSE:
		if (SendMessage(hwndEdit, EM_GETMODIFY, 0, 0))
		{
			LoadString(GetModuleHandle(0), IDS_CONFIRM, &s0, sizeof(s0) / sizeof(TCHAR));
			LoadString(GetModuleHandle(0), IDS_NOTSAVED, &s1, sizeof(s1) / sizeof(TCHAR));
			int ret = MessageBox(hwndMain, s1,
				s0, MB_YESNOCANCEL | MB_ICONEXCLAMATION);
			if (ret == IDCANCEL)
				return 0;
			if (ret == IDYES)
			{
				PostMessage(hwnd, WM_COMMAND, IDM_FILE_SAVE, 0);
				return 0;
			}
			else
				DestroyWindow(hwnd);
		}
		else
			DestroyWindow(hwnd);
		return 0;

	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;

	case WM_INITMENU:
		FlushMenus();
		break;

	case WM_COMMAND:
		switch(LOWORD(wParam))
		{
		case IDM_FILE_EXIT:
            PostQuitMessage(0);
 			break;

		case IDM_FILE_NEW:
		{
			uiFileEncoding = ENC_UTF8_BOM;
			uiFileEOL = EOL_CRLF;
			document_password[0] = (char)0;
			LoadString(GetModuleHandle(0), IDS_UNTITLED, &s0, sizeof(s0) / sizeof(TCHAR));
			SetWindowFileName(hwnd, s0);
			SendMessage(hwndEdit, WM_SETTEXT, 0, (LPARAM)_T(""));
			SendMessage(hwndEdit, EM_SETMODIFY, FALSE, 0);
			SendMessage(hwndEdit, EM_EMPTYUNDOBUFFER, 0, 0);
		}
			break;

		case IDM_FILE_OPEN:
			if (lParam == TRUE || ShowOpenFileDlg(hwnd, szFileName, szFileTitle))
			{
				if (! LoadFile())
					return FALSE;

				if (!SendMessage(hwndEdit, WM_SETTEXT, 0, (LPARAM)szEditBuffer))
				{
					LoadString(GetModuleHandle(0), IDS_NOTSET, &s0, sizeof(s0) / sizeof(TCHAR));
					LoadString(GetModuleHandle(0), IDS_ERROR, &s1, sizeof(s1) / sizeof(TCHAR));
					return MessageBox(hwnd, s0, s1, MB_OK | MB_ICONSTOP);
				}
				SetWindowFileName(hwnd, szFileTitle);
				Free(szEditBufferBase);
			}
            break;

		case IDM_FILE_SAVE:
			if (!szFileName[0])
			{
				SendMessage(hwnd, WM_COMMAND, IDM_FILE_SAVEAS, 0);
			}
			else
			{
				int cb = GetWindowTextLength(hwndEdit) * sizeof(TCHAR) + sizeof(TCHAR);
				szEditBuffer = Malloc(cb);
				GetWindowText(hwndEdit, szEditBuffer, cb);
				SaveFile(cb);
				Free(szEditBuffer);
				SetWindowFileName(hwnd, szFileTitle);
				SendMessage(hwndEdit, EM_SETMODIFY, FALSE, 0);
				SendMessage(hwndEdit, EM_EMPTYUNDOBUFFER, 0, 0);
			}
		break;

		case IDM_FILE_SAVEAS:
			if (ShowSaveAsFileDlg(hwnd, szFileName, szFileTitle))
				SendMessage(hwnd, WM_COMMAND, IDM_FILE_SAVE, 0);
			break;

		case IDM_HELP_ABOUT:
			ShowAboutDlg(hwnd);
			break;

		case IDM_FILE_PASSWORD:
			// lParam set to TRUE force an IDM_FILE_OPEN command 
			AskPassword(lParam);
			break;

		case ID_FILE_RESETPASSWORD:
			document_password[0] = NULL;
			break;

        case IDM_EDUNDO:
            // Send WM_UNDO only if there is something to be undone.
            if (SendMessage(hwndEdit, EM_CANUNDO, 0, 0))
                SendMessage(hwndEdit, WM_UNDO, 0, 0);
            break;

        case IDM_EDCUT:
            SendMessage(hwndEdit, WM_CUT, 0, 0);
            break;

        case IDM_EDCOPY:
            SendMessage(hwndEdit, WM_COPY, 0, 0);
            break;

        case IDM_EDPASTE:
            SendMessage(hwndEdit, WM_PASTE, 0, 0);
            break;

		case IDM_EDDEL:
			SendMessage(hwndEdit, WM_CLEAR, 0, 0);
			break;

		case IDM_EDALLSEL:
			SendMessage(hwndEdit, EM_SETSEL, 0, SendMessage(hwndEdit, WM_GETTEXTLENGTH, 0, 0));
			SendMessage(hwndEdit, EM_SCROLLCARET, 0, 0);
			EnableMenuItem(GetMenu(hwndMain), IDM_EDALLSEL, MF_GRAYED);
			break;

		case ID_ENCODING_UTF8BOM:
			uiFileEncoding = ENC_UTF8_BOM;
			break;
		case ID_ENCODING_UTF16LE:
			uiFileEncoding = ENC_UTF16LE;
			break;
		case ID_ENCODING_UTF16BE:
			uiFileEncoding = ENC_UTF16BE;
			break;
		case ID_ENCODING_ASCII:
			uiFileEncoding = ENC_ANSI;
			break;
		case ID_ENCODING_CRLF:
			uiFileEOL = EOL_CRLF;
			break;
		case ID_ENCODING_CR:
			uiFileEOL = EOL_CR;
			break;
		case ID_ENCODING_LF:
			uiFileEOL = EOL_LF;
			break;
		case EN_ERRSPACE:
			MessageBox(hwnd, _T("Max text!"), _T("Max text"), MB_OK);
			break;
		}
		break;

	case WM_SIZE:
		width  = (short)LOWORD(lParam);
		height = (short)HIWORD(lParam);
		MoveWindow(hwndEdit, 0, 0, width, height, TRUE);
		return 0;
	default:
		return DefWindowProc(hwnd, msg, wParam, lParam);
	}
}

//
//	Register main window class
//
void InitMainWnd()
{
	WNDCLASSEX wcx;
	HANDLE hInst = GetModuleHandle(0);

	// Window class for the main application parent window
	wcx.cbSize			= sizeof(wcx);
	wcx.style			= 0;
	wcx.lpfnWndProc		= WndProc;
	wcx.cbClsExtra		= 0;
	wcx.cbWndExtra		= 0;
	wcx.hInstance		= hInst;
	wcx.hCursor			= LoadCursor (NULL, IDC_ARROW);
	wcx.hbrBackground	= (HBRUSH)0;
	wcx.lpszMenuName	= MAKEINTRESOURCE(IDR_MENU1);
	wcx.lpszClassName	= szAppName;
	wcx.hIcon			= LoadImage(hInst, MAKEINTRESOURCE(IDI_ICON1), IMAGE_ICON, 32, 32, LR_CREATEDIBSECTION);
	wcx.hIconSm			= LoadImage(hInst, MAKEINTRESOURCE(IDI_ICON1), IMAGE_ICON, 16, 16, LR_CREATEDIBSECTION);

	RegisterClassEx(&wcx);
}

//
//	Create a top-level window
//
HWND CreateMainWnd()
{
	return CreateWindowEx(0,
				szAppName,				// window class name
				szAppName,				// window caption
				WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
				CW_USEDEFAULT,			// initial x position
				CW_USEDEFAULT,			// initial y position
				GetSystemMetrics(SM_CXSCREEN)/2, // initial x size
				GetSystemMetrics(SM_CYSCREEN)/2, // initial y size
				NULL,					// parent window handle
				NULL,					// use window class menu
				GetModuleHandle(0),		// program instance handle
				NULL);					// creation parameters
}

//
//	Entry-point for text-editor application
//
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int iShowCmd)
{
	MSG			msg;
	HACCEL		hAccel;

	// initialize window classes
	InitMainWnd();

	// create the main window!
	hwndMain = CreateMainWnd();

	ShowWindow(hwndMain, iShowCmd);
    UpdateWindow(hwndMain);

	// load keyboard accelerator table
	hAccel = LoadAccelerators(hInst, MAKEINTRESOURCE(IDR_ACCELERATOR1));

	szFileName[0]  = (TCHAR) 0;
	szFileTitle[0] = (TCHAR) 0;

	// message-loop
	while(GetMessage(&msg, NULL, 0, 0) > 0)
	{
		if(!TranslateAccelerator(hwndMain, hAccel, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return 0;
}
