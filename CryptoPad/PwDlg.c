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

#include <windows.h>
#include <tchar.h>

#include "resource.h"

extern HWND hwndMain;
extern char* document_password;

HWND hWndDialog;
WNDPROC wpOrigEditProc;
LRESULT WINAPI PasswordWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT WINAPI EditSubclassProc(HWND, UINT, WPARAM, LPARAM);

TCHAR password[40];
BOOL bSendOpenCommand;

void AskPassword(BOOL bForceOpen)
{
	bSendOpenCommand = bForceOpen;
	password[0] = (TCHAR) NULL;
	hWndDialog = CreateDialog(NULL, MAKEINTRESOURCE(IDD_DIALOG1), hwndMain, PasswordWndProc);
	wpOrigEditProc = (WNDPROC)SetWindowLong(GetDlgItem(hWndDialog, IDC_EDIT1), GWL_WNDPROC, (LONG)EditSubclassProc);
	ShowWindow(hWndDialog, SW_SHOWDEFAULT);
	SetFocus(GetDlgItem(hWndDialog, IDC_EDIT1));
}

LRESULT
CALLBACK
PasswordWndProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
   TCHAR pw[80];
   TCHAR s0[128], s1[128];

   pw[0] = (TCHAR)0;

   switch(msg)
   {
	  case WM_COMMAND:
		  if (LOWORD(wParam) == IDCANCEL)
			  DestroyWindow(hWnd);

		  if (LOWORD(wParam) == IDOK)
		  {
			  GetDlgItemText(hWnd, IDC_EDIT1, pw, 80);
			  if (lstrlen(pw) < 4)
			  {
				  DestroyWindow(hWnd);
				  LoadString(GetModuleHandle(0), IDS_ESHORTPW2, (LPWSTR) s0, sizeof(s0) / sizeof(TCHAR));
				  LoadString(GetModuleHandle(0), IDS_ESHORTPW1, (LPWSTR) s1, sizeof(s1) / sizeof(TCHAR));
				  MessageBox(NULL, s0, s1, MB_APPLMODAL | MB_TOPMOST | MB_ICONSTOP | MB_OK);
				  return 0;
			  }
			  if (!password[0])
			  {
				  lstrcpy(password, pw);
				  if (bSendOpenCommand) // Asks once
				  {
					  WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK | WC_NO_BEST_FIT_CHARS,
						  password, -1, document_password, 80, NULL, NULL);
					  PostMessage(hwndMain, WM_COMMAND, IDM_FILE_OPEN, TRUE);
					  DestroyWindow(hWnd);
				  }
				  SetDlgItemText(hWnd, IDC_EDIT1, _T(""));
				  LoadString(GetModuleHandle(0), IDS_RETYPE, (LPWSTR) s0, sizeof(s0) / sizeof(TCHAR));
				  SetDlgItemText(hWnd, IDC_STATIC1, s0);
				  SetFocus(GetDlgItem(hWnd, IDC_EDIT1));
				  return 0;
			  }
			  else
			  {
				  if (lstrcmp(pw, password))
				  {
					  DestroyWindow(hWnd);
					  LoadString(GetModuleHandle(0), IDS_EBADPW0, (LPWSTR) s0, sizeof(s0) / sizeof(TCHAR));
					  LoadString(GetModuleHandle(0), IDS_ENOMATCH, (LPWSTR) s1, sizeof(s1) / sizeof(TCHAR));
					  MessageBox(hwndMain, s1, s0, MB_APPLMODAL | MB_TOPMOST | MB_ICONSTOP | MB_OK);
					  password[0] = (TCHAR)0;
					  return 0;
				  }
				  else
				  {
					  WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK|WC_NO_BEST_FIT_CHARS, password, -1, document_password, 80, NULL, NULL);
				  }
				  SetFocus(GetParent(hWnd));
				  DestroyWindow(hWnd);
			  }
		  }
		  break;

      default:
         return DefWindowProc(hWnd, msg, wParam, lParam);
   }

   return 0;
}

LRESULT APIENTRY EditSubclassProc(
	HWND hwnd,
	UINT uMsg,
	WPARAM wParam,
	LPARAM lParam)
{
	if (uMsg == WM_KEYDOWN)
	{
		if (wParam == VK_RETURN)
			SendMessage(hWndDialog, WM_COMMAND, IDOK, 0);
		if (wParam == VK_ESCAPE)
			SendMessage(hWndDialog, WM_COMMAND, IDCANCEL, 0);
	}

	if (wParam == VK_RETURN)
		return 0; // Suppress annoying BEEP

	return CallWindowProc(wpOrigEditProc, hwnd, uMsg, wParam, lParam);
}
