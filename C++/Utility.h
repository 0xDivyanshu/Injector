#pragma once
#include"internals.h"

typedef std::string string;

class Utility
{
	public:
		LPWSTR string_to_lpwstr(string s) {
			USES_CONVERSION_EX;
			LPWSTR lp = A2W_EX(s.c_str(), s.length());
			return lp;
		}
		LPSTR string_to_lpstr(string s) {
			LPSTR res = const_cast<char*>(s.c_str());
			return res;
		}
		LPCWSTR s2pw(const string s)
		{
			int len;
			int slength = (int)s.length() + 1;
			len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
			wchar_t* buf = new wchar_t[len];
			MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
			return buf;
		}
		int get_len_w(PWCHAR text) {
			int i = 0;
			while (text[i] != '\0') {
				i = i + 1;
			}
			return i;
		}

		char* convert_pwchar_str(PWCHAR text) {
			int len = get_len_w(text) + 1;
			char* res = (char*)malloc(len);
			wcstombs(res, text, get_len_w(text) + 1);
			return res;
		}
};
