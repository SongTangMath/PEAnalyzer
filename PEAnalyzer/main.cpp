#include <windows.h>
#include "resource.h"
#include <string>
#include <vector>
#include <map>
LRESULT CALLBACK WndProc (HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK AboutDlgProc (HWND , UINT, WPARAM, LPARAM);
int AnalyzePEFile(char* filebuffer,int len,IMAGE_DOS_HEADER* pimage_dos_header,IMAGE_NT_HEADERS* pimage_nt_headers,
				  std::vector<IMAGE_SECTION_HEADER>&vec);
std::wstring CollectInformationFromIMAGE_DOS_HEADER(IMAGE_DOS_HEADER image_dos_header);
std::wstring CollectInformationFromIMAGE_NT_HEADERS(IMAGE_NT_HEADERS image_nt_headers);
std::wstring CollectInformationFromIMAGE_SECTION_HEADER(IMAGE_SECTION_HEADER image_section_header);
std::wstring CollectInformationFromIMAGE_DATA_DIRECTORY(char* filebuffer,unsigned int filelen,
			IMAGE_DATA_DIRECTORY* pimage_data_directory,std::vector<IMAGE_SECTION_HEADER>&vec);
std::wstring CollectInformationFromIMAGE_EXPORT_DIRECTORY(char* filebuffer,unsigned int filelen,
	std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_EXPORT_DIRECTORY image_export_directory);
std::wstring CollectInformationFromIMAGE_IMPORT_DESCRIPTOR (char* filebuffer,unsigned int filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_IMPORT_DESCRIPTOR image_import_descriptor);


std::wstring GetNameFromFileOffset(char* filebuffer,unsigned int filelen,unsigned int offset);
std::wstring MultiCharToWideString(const char* str);
std::wstring GetNameFromRVA(char* filebuffer,unsigned int filelen,std::vector<IMAGE_SECTION_HEADER>&vec,unsigned int RVA);
int RVAToFOA(std::vector<IMAGE_SECTION_HEADER>&vec,unsigned int RVA);
bool operator==(const IMAGE_SECTION_HEADER &a, const IMAGE_SECTION_HEADER &b);
bool operator!=(const IMAGE_SECTION_HEADER &a, const IMAGE_SECTION_HEADER &b);
bool operator==(const IMAGE_IMPORT_DESCRIPTOR &a, const IMAGE_IMPORT_DESCRIPTOR &b);
bool operator!=(const IMAGE_IMPORT_DESCRIPTOR &a, const IMAGE_IMPORT_DESCRIPTOR &b);
bool operator==(const IMAGE_THUNK_DATA &a, const IMAGE_THUNK_DATA &b);
bool operator!=(const IMAGE_THUNK_DATA &a, const IMAGE_THUNK_DATA &b);

int WINAPI WinMain(HINSTANCE hInstance,HINSTANCE hPrevstance,LPSTR   IpCmdLine,int iCmdShow)
{
	HMENU hmenu;
	static TCHAR szAppName[]=TEXT("TS PEAnalyzer for 64bit PE");
	HWND hwnd;
	MSG msg;
	WNDCLASS wndclass;
	hmenu=LoadMenuW(hInstance,MAKEINTRESOURCE(IDR_MENU1));
	wndclass.style=CS_VREDRAW|CS_HREDRAW|CS_DBLCLKS;
	wndclass.lpfnWndProc=WndProc;
	wndclass.cbClsExtra=0;
	wndclass.cbWndExtra = 0 ;
	wndclass.hInstance = hInstance ;
	wndclass.hIcon = LoadIcon (NULL, IDI_APPLICATION) ;
	wndclass.hCursor = LoadCursor (NULL, IDC_ARROW) ;
	wndclass.hbrBackground = (HBRUSH) GetStockObject (WHITE_BRUSH) ;
	wndclass.lpszMenuName =NULL ;
	wndclass.lpszClassName = szAppName ;
	if(!RegisterClass(&wndclass))
	{
		MessageBox(NULL,L"Failed to create window",L"Warning",0);
		return 0;
	}   
	hwnd = CreateWindow ( szAppName, TEXT ("TS PEAnalyzer for 64bit PE"),
		WS_OVERLAPPEDWINDOW^WS_SIZEBOX^WS_MAXIMIZEBOX,
		10, 10,
		1200, 800,
		NULL, hmenu, hInstance, NULL) ;
	ShowWindow(hwnd,iCmdShow);
	UpdateWindow(hwnd);
	while(GetMessage(&msg,NULL,0,0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return msg.wParam;
}
LRESULT CALLBACK WndProc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{ 
	static HINSTANCE hInstance ;
	static HWND subwindows[25];
	HDC hdc;
	PAINTSTRUCT ps;
	OPENFILENAME ofn;
	TCHAR szFilename[MAX_PATH];
	IMAGE_DOS_HEADER image_dos_header;
	IMAGE_NT_HEADERS image_nt_headers;
	//IMAGE_EXPORT_DIRECTORY image_export_directory;
	std::vector<IMAGE_SECTION_HEADER> vec;
	static HFONT hfont=CreateFontW(20,0,0,0,0,0,0,0,
		ANSI_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
		DEFAULT_QUALITY,DEFAULT_PITCH,L"Consolas");

	switch(message)
	{
	case WM_CREATE:
		hInstance = ((LPCREATESTRUCT) lParam)->hInstance ;
		subwindows[0]=CreateWindow(TEXT("static"),TEXT("IMAGE_DOS_HEADER"),WS_BORDER|WS_CHILD | WS_VISIBLE | SS_LEFT ,
			0,0,150,25,hwnd,(HMENU)0,hInstance,NULL);
		subwindows[1]=CreateWindow(TEXT("edit"),TEXT(""),
			WS_CHILD | WS_VISIBLE|WS_BORDER|WS_HSCROLL|WS_VSCROLL | ES_AUTOHSCROLL|ES_AUTOVSCROLL|ES_MULTILINE|ES_WANTRETURN,
			0,25,550,300,hwnd,(HMENU)1,hInstance,NULL);

		subwindows[2]=CreateWindow(TEXT("static"),TEXT("IMAGE_NT_HEADERS"),WS_BORDER|WS_CHILD | WS_VISIBLE | SS_LEFT ,
			0,350,150,25,hwnd,(HMENU)2,hInstance,NULL);
		subwindows[3]=CreateWindow(TEXT("edit"),TEXT(""),
			WS_CHILD | WS_VISIBLE|WS_BORDER|WS_HSCROLL|WS_VSCROLL | ES_AUTOHSCROLL|ES_AUTOVSCROLL|ES_MULTILINE|ES_WANTRETURN,
			0,375,550,300,hwnd,(HMENU)3,hInstance,NULL);

		subwindows[4]=CreateWindow(TEXT("static"),TEXT("IMAGE_SECTION_HEADER"),WS_BORDER|WS_CHILD | WS_VISIBLE | SS_LEFT ,
			570,0,190,25,hwnd,(HMENU)4,hInstance,NULL);
		subwindows[5]=CreateWindow(TEXT("edit"),TEXT(""),
			WS_CHILD | WS_VISIBLE|WS_BORDER|WS_HSCROLL|WS_VSCROLL | ES_AUTOHSCROLL|ES_AUTOVSCROLL|ES_MULTILINE|ES_WANTRETURN,
			570,25,500,300,hwnd,(HMENU)5,hInstance,NULL);

		subwindows[6]=CreateWindow(TEXT("static"),TEXT("IMAGE_DATA_DIRECTORY"),WS_BORDER|WS_CHILD | WS_VISIBLE | SS_LEFT ,
			570,350,190,25,hwnd,(HMENU)6,hInstance,NULL);
		subwindows[7]=CreateWindow(TEXT("edit"),TEXT(""),
			WS_CHILD | WS_VISIBLE|WS_BORDER|WS_HSCROLL|WS_VSCROLL | ES_AUTOHSCROLL|ES_AUTOVSCROLL|ES_MULTILINE|ES_WANTRETURN,
			570,375,500,300,hwnd,(HMENU)7,hInstance,NULL);

		for(int i=0;i<sizeof(subwindows)/sizeof(subwindows[0]);i++)
			SendMessage(subwindows[i],WM_SETFONT,(WPARAM)hfont,0);
		return 0 ;

	case WM_PAINT:
		hdc=BeginPaint(hwnd,&ps);		
		EndPaint(hwnd,&ps);
		return 0;

	case WM_DESTROY :
		PostQuitMessage (0) ;
		return 0 ;

	case WM_COMMAND:
		switch(LOWORD(wParam))
		{
		case  ID_PEFILE_OPEN:
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = hwnd;
			ofn.lpstrFile = szFilename;
			ofn.lpstrFile[0] = '\0';
			ofn.nMaxFile = sizeof(szFilename);
			ofn.lpstrFilter = TEXT("PE files (*.exe;*.dll)\0*.exe;*.dll\0\0");
			ofn.nFilterIndex = 1;
			ofn.lpstrFileTitle = NULL;
			ofn.nMaxFileTitle = 0;
			ofn.lpstrInitialDir = NULL;
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
			ofn.lpstrTitle = TEXT("open");
			if (GetOpenFileName(&ofn))
				SetWindowText(hwnd,szFilename);
			else MessageBox(NULL,TEXT("some error found"),TEXT("hints"),0);

			HANDLE hfile=CreateFile(szFilename,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
			if(hfile==INVALID_HANDLE_VALUE){
				MessageBox(NULL,TEXT("argument incorrect"),TEXT("hints"),0);
				break;
			}
			DWORD filelen=GetFileSize(hfile,NULL);
			if(filelen<sizeof(IMAGE_DOS_HEADER)){
				MessageBox(NULL,TEXT("this is not a valid PE file"),TEXT("hints"),0);
				break;
			}	
			char* filebuffer=new char[filelen];
			ZeroMemory(filebuffer,sizeof(filebuffer));
			ReadFile(hfile,filebuffer,filelen,NULL,NULL);
			int ret= AnalyzePEFile(filebuffer,filelen,&image_dos_header,&image_nt_headers,vec);
			if(ret<0)break;

			SetWindowText(subwindows[1],CollectInformationFromIMAGE_DOS_HEADER(image_dos_header).c_str());
			SetWindowText(subwindows[3],CollectInformationFromIMAGE_NT_HEADERS(image_nt_headers).c_str());
			wchar_t buf[256];
			wsprintf(buf,L"count of image_section_header:%d\r\n",vec.size());
			std::wstring s=buf;
			for(int i=0;i<vec.size();i++){
				wsprintf(buf,L"image_section_headers[%d]\r\n",i);
				s+=buf;
				s+=CollectInformationFromIMAGE_SECTION_HEADER(vec[i]);
				s+=TEXT("\r\n");
			}
			SetWindowText(subwindows[5],s.c_str());		
			SetWindowText(subwindows[7],
			CollectInformationFromIMAGE_DATA_DIRECTORY(filebuffer,filelen,image_nt_headers.OptionalHeader.DataDirectory,vec).c_str());

			delete[]filebuffer;
			CloseHandle(hfile);
			break;


		}
		break;

	}
	return DefWindowProc (hwnd, message, wParam, lParam) ;
}

int AnalyzePEFile(char* filebuffer,int filelen,IMAGE_DOS_HEADER* pimage_dos_header,
				  IMAGE_NT_HEADERS* pimage_nt_headers,std::vector<IMAGE_SECTION_HEADER>&vec)
	{

	if(pimage_dos_header==NULL||pimage_nt_headers==NULL)return -1;
	memcpy(pimage_dos_header,filebuffer,sizeof(IMAGE_DOS_HEADER));
	if(pimage_dos_header->e_magic!=0x5a4d)return -2;		
	if(pimage_dos_header->e_lfanew+sizeof(IMAGE_NT_HEADERS)>=filelen)return -2;
	memcpy(pimage_nt_headers,filebuffer+pimage_dos_header->e_lfanew,sizeof(IMAGE_NT_HEADERS));

	if(pimage_nt_headers->FileHeader.Machine!=IMAGE_FILE_MACHINE_IA64 &&
		pimage_nt_headers->FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64){
		MessageBox(0,TEXT("this image is not a 64bit image"),TEXT("hints"),0);
		return -1;
	}
	int image_section_header_begin_position= pimage_dos_header->e_lfanew+sizeof(IMAGE_NT_HEADERS);

	IMAGE_SECTION_HEADER image_section_header_zero;
	image_section_header_zero.Characteristics=0;
	image_section_header_zero.Misc.PhysicalAddress=0;
	for(int i=0;i<IMAGE_SIZEOF_SHORT_NAME;i++)
	image_section_header_zero.Name[i]=0;
	image_section_header_zero.NumberOfLinenumbers=0;
	image_section_header_zero.NumberOfRelocations=0;
	image_section_header_zero.PointerToLinenumbers=0;
	image_section_header_zero.PointerToRawData=0;
	image_section_header_zero.PointerToRelocations=0;
	image_section_header_zero.SizeOfRawData=0;
	image_section_header_zero.VirtualAddress=0;
	while(image_section_header_begin_position+sizeof(IMAGE_SECTION_HEADER)<filelen&& 
	(*(IMAGE_SECTION_HEADER*)(filebuffer+image_section_header_begin_position))!=image_section_header_zero)
	  {
		  vec.push_back(*(IMAGE_SECTION_HEADER*)(filebuffer+image_section_header_begin_position));
		  image_section_header_begin_position+=sizeof(IMAGE_SECTION_HEADER);
	  }
	
 return 0;
}
bool operator==(const IMAGE_SECTION_HEADER &a, const IMAGE_SECTION_HEADER &b){
	bool flag= (a.Characteristics==b.Characteristics&&
		a.Misc.PhysicalAddress==b.Misc.PhysicalAddress&&

		a.NumberOfLinenumbers==b.NumberOfLinenumbers&&
		a.NumberOfRelocations==b.NumberOfRelocations&&
		a.PointerToLinenumbers==b.PointerToLinenumbers&&
		a.PointerToRawData==b.PointerToRawData&&
		a.PointerToRelocations==b.PointerToRelocations&&
		a.SizeOfRawData==b.SizeOfRawData&&
		a.VirtualAddress==b.VirtualAddress);
	for(int i=0;i<IMAGE_SIZEOF_SHORT_NAME;i++)
		if(a.Name[i]!=b.Name[i])flag=false;
	return flag;
}
bool operator!=(const IMAGE_SECTION_HEADER &a, const IMAGE_SECTION_HEADER &b){return ! (a==b);}
bool operator==(const IMAGE_IMPORT_DESCRIPTOR &a, const IMAGE_IMPORT_DESCRIPTOR &b){
	return	a.Characteristics==b.Characteristics&&
			a.FirstThunk==b.FirstThunk&&
			a.ForwarderChain==b.ForwarderChain&&
			a.Name==b.Name&&
			a.OriginalFirstThunk==b.OriginalFirstThunk&&
			a.TimeDateStamp==b.TimeDateStamp;
}
bool operator!=(const IMAGE_IMPORT_DESCRIPTOR &a, const IMAGE_IMPORT_DESCRIPTOR &b){return !(a==b);}
bool operator==(const IMAGE_THUNK_DATA &a, const IMAGE_THUNK_DATA &b){
	return a.u1.AddressOfData==b.u1.AddressOfData;
}
bool operator!=(const IMAGE_THUNK_DATA &a, const IMAGE_THUNK_DATA &b){return !(a==b);}
std::wstring CollectInformationFromIMAGE_DOS_HEADER(IMAGE_DOS_HEADER image_dos_header){
	wchar_t buf[64];
	std::wstring s=TEXT("WORD e_magic: // Magic DOS signature MZ(4Dh 5Ah)\r\n");
	s+=TEXT("魔数,DOS可执行文件标记\r\n");
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_magic);
	s+=buf;

	s+=TEXT("WORD  e_cblp  // Bytes on last page of file\r\n");
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_cblp);
	s+=buf;

	s+=TEXT("WORD  e_cp   // Pages in file \r\n");
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_cp);
	s+=buf;

	s+=TEXT("WORD  e_crlc   // Relocations \r\n");
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_crlc);
	s+=buf;

	s+=TEXT("WORD  e_cparhdr   // Size of header in paragraphs \r\n");
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_cparhdr);
	s+=buf;

	s+=TEXT("WORD  e_minalloc  // Minimun extra paragraphs needs \r\n");
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_minalloc);
	s+=buf;

	s+=TEXT("WORD  e_maxalloc  // Maximun extra paragraphs needs  \r\n");
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_maxalloc);
	s+=buf;

	s+=TEXT("WORD  e_ss    // intial(relative)SS value\r\n");
	s+=TEXT("DOS代码的初始化堆栈SS\r\n");
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_ss);
	s+=buf;

	s+=TEXT("WORD  e_sp    // intial SP value\r\n");
	s+=TEXT("DOS代码的初始化堆栈指针SP\r\n");
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_sp);
	s+=buf;

	s+=TEXT("WORD  e_csum    // Checksum \r\n");							
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_csum);
	s+=buf;

	s+=TEXT("WORD  e_ip    //    intial IP value\r\n");
	s+=TEXT("DOS代码的初始化指令入口[指针IP] \r\n");
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_ip);
	s+=buf;

	s+=TEXT("WORD  e_cs    // intial(relative)CS value \r\n");
	s+=TEXT("DOS代码的初始堆栈入口\r\n");
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_cs);
	s+=buf;

	s+=TEXT("WORD  e_lfarlc    // File Address of relocation table\r\n");							
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_lfarlc);
	s+=buf;

	s+=TEXT("WORD  e_ovno        //    Overlay number \r\n");							
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_ovno);
	s+=buf;

	s+=TEXT("WORD  e_res[4]    // Reserved words\r\n");							
	wsprintf(buf,L"0x%x,0x%x,0x%x,0x%x\r\n",image_dos_header.e_res[0]
	,image_dos_header.e_res[1],image_dos_header.e_res[2],image_dos_header.e_res[3]);
	s+=buf;

	s+=TEXT("WORD  e_oemid    //    OEM identifier(for e_oeminfo) \r\n");							
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_oemid);
	s+=buf;

	s+=TEXT("WORD      e_oeminfo   //    OEM information;e_oemid specific \r\n");							
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_oeminfo);
	s+=buf;

	s+=TEXT("WORD  e_res2[10]   //    Reserved words  \r\n");	
	for(int i=0;i<10;i++){
		wsprintf(buf,L"0x%x ",image_dos_header.e_res2[i]);
		s+=buf;
	}
	s+=TEXT("\r\n");

	s+=TEXT("DWORD   e_lfanew     // Offset to start of PE header \r\n");	
	s+=TEXT("指向PE文件头 \r\n");
	wsprintf(buf,L"0x%x\r\n",image_dos_header.e_lfanew);
	s+=buf;

	return s;
}

std::wstring CollectInformationFromIMAGE_NT_HEADERS(IMAGE_NT_HEADERS image_nt_headers){
	wchar_t buf[64];
	std::wstring s=TEXT("DWORD Signature 魔数, 00004550h\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.Signature);
	s+=buf;
	s+=TEXT("下面是IMAGE_FILE_HEADER部分\r\n");

	s+=TEXT("WORD  Machine \r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.FileHeader.Machine);
	s+=buf;

	s+=TEXT("WORD  NumberOfSections \r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.FileHeader.NumberOfSections);
	s+=buf;

	s+=TEXT("DWORD TimeDateStamp \r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.FileHeader.TimeDateStamp);
	s+=buf;

	s+=TEXT("DWORD PointerToSymbolTable \r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.FileHeader.PointerToSymbolTable);
	s+=buf;

	s+=TEXT("DWORD NumberOfSymbols \r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.FileHeader.NumberOfSymbols);
	s+=buf;

	s+=TEXT("WORD  SizeOfOptionalHeader\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.FileHeader.SizeOfOptionalHeader);
	s+=buf;

	s+=TEXT("WORD  Characteristics\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.FileHeader.Characteristics);
	s+=buf;

	s+=TEXT("下面是IMAGE_OPTIONAL_HEADER64部分\r\n");
	s+=TEXT("WORD                 Magic\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.Magic);
	s+=buf;

	s+=TEXT("BYTE                 MajorLinkerVersion\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.MajorLinkerVersion);
	s+=buf;

	s+=TEXT("BYTE                 MinorLinkerVersion;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.MinorLinkerVersion);
	s+=buf;

	s+=TEXT("DWORD                SizeOfCode;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.SizeOfCode);
	s+=buf;

	s+=TEXT("DWORD                SizeOfInitializedData;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.SizeOfInitializedData);
	s+=buf;

	s+=TEXT("DWORD                SizeOfUninitializedData;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.SizeOfUninitializedData);
	s+=buf;

	s+=TEXT("DWORD                AddressOfEntryPoint;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.AddressOfEntryPoint);
	s+=buf;

	s+=TEXT("DWORD                BaseOfCode;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.BaseOfCode);
	s+=buf;

	s+=TEXT("ULONGLONG            ImageBase;\r\n");	
	swprintf(buf,255,L"%llx\r\n",image_nt_headers.OptionalHeader.ImageBase);	
	s+=buf;

	s+=TEXT("DWORD                SectionAlignment;\r\n");

	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.SectionAlignment);
	s+=buf;

	s+=TEXT("DWORD                FileAlignment;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.FileAlignment);
	s+=buf;

	s+=TEXT("WORD                 MajorOperatingSystemVersion;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.MajorOperatingSystemVersion);
	s+=buf;

	s+=TEXT("WORD                 MinorOperatingSystemVersion;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.MinorOperatingSystemVersion);
	s+=buf;

	s+=TEXT("WORD                 MajorImageVersion;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.MajorImageVersion);
	s+=buf;

	s+=TEXT("WORD                 MinorImageVersion;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.MinorImageVersion);
	s+=buf;

	s+=TEXT("WORD                 MajorSubsystemVersion;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.MajorSubsystemVersion);
	s+=buf;

	s+=TEXT("WORD                 MinorSubsystemVersion;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.MinorSubsystemVersion);
	s+=buf;

	s+=TEXT("DWORD                Win32VersionValue;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.Win32VersionValue);
	s+=buf;

	s+=TEXT("DWORD                SizeOfImage;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.SizeOfImage);
	s+=buf;

	s+=TEXT("DWORD                SizeOfHeaders;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.SizeOfHeaders);
	s+=buf;

	s+=TEXT("DWORD                CheckSum;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.CheckSum);
	s+=buf;

	s+=TEXT("WORD                 Subsystem;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.Subsystem);
	s+=buf;

	s+=TEXT("WORD                 DllCharacteristics;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.DllCharacteristics);
	s+=buf;

	s+=TEXT("ULONGLONG            SizeOfStackReserve;\r\n");
	swprintf(buf,255,L"0x%llx\r\n",image_nt_headers.OptionalHeader.SizeOfStackReserve);
	s+=buf;

	s+=TEXT("ULONGLONG            SizeOfStackCommit;\r\n");
	swprintf(buf,255,L"0x%llx\r\n",image_nt_headers.OptionalHeader.SizeOfStackCommit);
	s+=buf;

	s+=TEXT("ULONGLONG            SizeOfHeapReserve;\r\n");
	swprintf(buf,255,L"0x%llx\r\n",image_nt_headers.OptionalHeader.SizeOfHeapReserve);
	s+=buf;

	s+=TEXT("ULONGLONG            SizeOfHeapCommit;\r\n");
	swprintf(buf,255,L"0x%llx\r\n",image_nt_headers.OptionalHeader.SizeOfHeapCommit);
	s+=buf;

	s+=TEXT("DWORD                LoaderFlags;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.LoaderFlags);
	s+=buf;

	s+=TEXT("DWORD                NumberOfRvaAndSizes;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.OptionalHeader.NumberOfRvaAndSizes);
	s+=buf;

	s+=TEXT("IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];\r\n");
	s+=TEXT("IMAGE_NUMBEROF_DIRECTORY_ENTRIES=16\r\n\r\n");

	wsprintf(buf,L"DataDirectory[%d]=IMAGE_DIRECTORY_ENTRY_EXPORT\r\n",IMAGE_DIRECTORY_ENTRY_EXPORT);
	s+=buf;
	wsprintf(buf,L"VirtualAddress=0x%x,Size=0x%x\r\n",
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
	s+=buf;

	wsprintf(buf,L"DataDirectory[%d]=IMAGE_DIRECTORY_ENTRY_IMPORT    \r\n",IMAGE_DIRECTORY_ENTRY_IMPORT    );
	s+=buf;
	wsprintf(buf,L"VirtualAddress=0x%x,Size=0x%x\r\n",
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT    ].VirtualAddress,
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT    ].Size);
	s+=buf;

	wsprintf(buf,L"DataDirectory[%d]=IMAGE_DIRECTORY_ENTRY_RESOURCE    \r\n",IMAGE_DIRECTORY_ENTRY_RESOURCE    );
	s+=buf;
	wsprintf(buf,L"VirtualAddress=0x%x,Size=0x%x\r\n",
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE    ].VirtualAddress,
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE    ].Size);
	s+=buf;

	wsprintf(buf,L"DataDirectory[%d]=IMAGE_DIRECTORY_ENTRY_EXCEPTION     \r\n",IMAGE_DIRECTORY_ENTRY_EXCEPTION     );
	s+=buf;
	wsprintf(buf,L"VirtualAddress=0x%x,Size=0x%x\r\n",
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION     ].VirtualAddress,
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION     ].Size);
	s+=buf;

	wsprintf(buf,L"DataDirectory[%d]=IMAGE_DIRECTORY_ENTRY_SECURITY      \r\n",IMAGE_DIRECTORY_ENTRY_SECURITY      );
	s+=buf;
	wsprintf(buf,L"VirtualAddress=0x%x,Size=0x%x\r\n",
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY      ].VirtualAddress,
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY      ].Size);
	s+=buf;

	wsprintf(buf,L"DataDirectory[%d]=IMAGE_DIRECTORY_ENTRY_BASERELOC     \r\n",IMAGE_DIRECTORY_ENTRY_BASERELOC     );
	s+=buf;
	wsprintf(buf,L"VirtualAddress=0x%x,Size=0x%x\r\n",
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC     ].VirtualAddress,
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC     ].Size);
	s+=buf;

	wsprintf(buf,L"DataDirectory[%d]=IMAGE_DIRECTORY_ENTRY_DEBUG     \r\n",IMAGE_DIRECTORY_ENTRY_DEBUG     );
	s+=buf;
	wsprintf(buf,L"VirtualAddress=0x%x,Size=0x%x\r\n",
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG     ].VirtualAddress,
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG     ].Size);
	s+=buf;

	wsprintf(buf,L"DataDirectory[%d]=IMAGE_DIRECTORY_ENTRY_ARCHITECTURE      \r\n",IMAGE_DIRECTORY_ENTRY_ARCHITECTURE      );
	s+=buf;
	wsprintf(buf,L"VirtualAddress=0x%x,Size=0x%x\r\n",
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE      ].VirtualAddress,
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE      ].Size);
	s+=buf;

	wsprintf(buf,L"DataDirectory[%d]=IMAGE_DIRECTORY_ENTRY_GLOBALPTR     \r\n",IMAGE_DIRECTORY_ENTRY_GLOBALPTR     );
	s+=buf;
	wsprintf(buf,L"VirtualAddress=0x%x,Size=0x%x\r\n",
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR     ].VirtualAddress,
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR     ].Size);
	s+=buf;

	wsprintf(buf,L"DataDirectory[%d]=IMAGE_DIRECTORY_ENTRY_TLS        \r\n",IMAGE_DIRECTORY_ENTRY_TLS        );
	s+=buf;
	wsprintf(buf,L"VirtualAddress=0x%x,Size=0x%x\r\n",
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS        ].VirtualAddress,
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS        ].Size);
	s+=buf;

	wsprintf(buf,L"DataDirectory[%d]=IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG        \r\n",IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG        );
	s+=buf;
	wsprintf(buf,L"VirtualAddress=0x%x,Size=0x%x\r\n",
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG        ].VirtualAddress,
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG        ].Size);
	s+=buf;

	wsprintf(buf,L"DataDirectory[%d]=IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT       \r\n",IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT       );
	s+=buf;
	wsprintf(buf,L"VirtualAddress=0x%x,Size=0x%x\r\n",
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT       ].VirtualAddress,
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT       ].Size);
	s+=buf;

	wsprintf(buf,L"DataDirectory[%d]=IMAGE_DIRECTORY_ENTRY_IAT        \r\n",IMAGE_DIRECTORY_ENTRY_IAT        );
	s+=buf;
	wsprintf(buf,L"VirtualAddress=0x%x,Size=0x%x\r\n",
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT        ].VirtualAddress,
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT        ].Size);
	s+=buf;

	wsprintf(buf,L"DataDirectory[%d]=IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT       \r\n",IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT       );
	s+=buf;
	wsprintf(buf,L"VirtualAddress=0x%x,Size=0x%x\r\n",
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT       ].VirtualAddress,
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT       ].Size);
	s+=buf;
	

	wsprintf(buf,L"DataDirectory[%d]=IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR     \r\n",IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR     );
	s+=buf;
	wsprintf(buf,L"VirtualAddress=0x%x,Size=0x%x\r\n",
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR     ].VirtualAddress,
		image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR     ].Size);
	s+=buf;

	wsprintf(buf,L"DataDirectory[%d]=Reserved    \r\n",15     );
	s+=buf;
	wsprintf(buf,L"VirtualAddress=0x%x,Size=0x%x\r\n",
		image_nt_headers.OptionalHeader.DataDirectory[15     ].VirtualAddress,
		image_nt_headers.OptionalHeader.DataDirectory[15     ].Size);
	s+=buf;

	return s;

}

std::wstring CollectInformationFromIMAGE_SECTION_HEADER(IMAGE_SECTION_HEADER image_section_header){
	wchar_t buf[64];
	std::wstring s=TEXT("BYTE  Name[IMAGE_SIZEOF_SHORT_NAME=8];\r\n");	
	size_t convertedChars=0;	
	mbstowcs_s(&convertedChars,buf,IMAGE_SIZEOF_SHORT_NAME,(const char*)image_section_header.Name,_TRUNCATE);
	//s+=TEXT("\"");
	s+=buf;
	s+=TEXT("\r\n");

	s+=TEXT("union {DWORD PhysicalAddress; DWORD VirtualSize;} Misc\r\n");
	wsprintf(buf,L"0x%x\r\n",image_section_header.Misc);
	s+=buf;

	s+=TEXT("DWORD VirtualAddress;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_section_header.VirtualAddress);
	s+=buf;

	s+=TEXT("DWORD SizeOfRawData;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_section_header.SizeOfRawData);
	s+=buf;

	s+=TEXT("DWORD PointerToRawData;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_section_header.PointerToRawData);
	s+=buf;

	s+=TEXT("DWORD PointerToRelocations;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_section_header.PointerToRelocations);
	s+=buf;

	s+=TEXT("DWORD PointerToLinenumbers;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_section_header.PointerToLinenumbers);
	s+=buf;

	s+=TEXT("WORD  NumberOfRelocations;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_section_header.NumberOfRelocations);
	s+=buf;

	s+=TEXT("WORD  NumberOfLinenumbers;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_section_header.NumberOfLinenumbers);
	s+=buf;

	s+=TEXT("DWORD Characteristics;\r\n");
	wsprintf(buf,L"0x%x\r\n",image_section_header.Characteristics);
	s+=buf;

	return s;
}

std::wstring CollectInformationFromIMAGE_DATA_DIRECTORY(char* filebuffer,unsigned int filelen,
	IMAGE_DATA_DIRECTORY* pimage_data_directory,std::vector<IMAGE_SECTION_HEADER>&vec){
	
	unsigned int FOA=0;
	wchar_t buf[256];
	std::vector<IMAGE_IMPORT_DESCRIPTOR>image_import_descriptor_vector;
	IMAGE_IMPORT_DESCRIPTOR image_import_descriptor_zero;
	image_import_descriptor_zero.Characteristics=0;
	image_import_descriptor_zero.FirstThunk=0;
	image_import_descriptor_zero.ForwarderChain=0;
	image_import_descriptor_zero.Name=0;
	image_import_descriptor_zero.OriginalFirstThunk=0;
	image_import_descriptor_zero.TimeDateStamp=0;

	std::wstring s=TEXT("");
	

	if(pimage_data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress){	
	FOA=RVAToFOA(vec,pimage_data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	s+=TEXT("image_data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT=0]导出表\r\n");
	s+=CollectInformationFromIMAGE_EXPORT_DIRECTORY(filebuffer,filelen,vec,*(IMAGE_EXPORT_DIRECTORY*)(filebuffer+FOA));	
	}
	else s+=TEXT("no IMAGE_EXPORT_DIRECTORY found in this image\r\n");
	s+=TEXT("\r\n");


	if(pimage_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress){
		IMAGE_IMPORT_DESCRIPTOR* pimage_import_descriptor=(IMAGE_IMPORT_DESCRIPTOR*)
			(filebuffer+RVAToFOA(vec,pimage_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
		while(*pimage_import_descriptor!=image_import_descriptor_zero)
		{
			image_import_descriptor_vector.push_back(*pimage_import_descriptor);
			pimage_import_descriptor++;
		}
		wsprintf(buf,L"count of image_import_descriptor = %d\r\n",image_import_descriptor_vector.size());
		s+=buf;
		for(int i=0;i<image_import_descriptor_vector.size();i++)
		{
			wsprintf(buf,L"image_import_descriptor[%d]\r\n",i);
			s+=buf;
			s+=CollectInformationFromIMAGE_IMPORT_DESCRIPTOR(filebuffer,filelen,vec,image_import_descriptor_vector[i]);
			s+=TEXT("\r\n");
		}
	}
	else s+=TEXT("no IMAGE_IMPORT_DESCRIPTOR found in this image\r\n");


	return s;
	}
std::wstring CollectInformationFromIMAGE_EXPORT_DIRECTORY(char* filebuffer,unsigned int filelen,
	std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_EXPORT_DIRECTORY image_export_directory){
	wchar_t buf[256];
	size_t convertedChars=0;
	std::wstring s=TEXT("");
	s+=TEXT("DWORD   Characteristics\r\n");
		

	wsprintf(buf,L"0x%x\r\n",image_export_directory.Characteristics);
	s+=buf;

	s+=TEXT("DWORD   TimeDateStamp\r\n");
	wsprintf(buf,L"0x%x\r\n",image_export_directory.TimeDateStamp);
	s+=buf;

	s+=TEXT("WORD    MajorVersion\r\n");
	wsprintf(buf,L"0x%x\r\n",image_export_directory.MajorVersion);
	s+=buf;

	s+=TEXT("WORD    MinorVersion\r\n");
	wsprintf(buf,L"0x%x\r\n",image_export_directory.MinorVersion);
	s+=buf;

	s+=TEXT("DWORD   Name\r\n");
	wsprintf(buf,L"0x%x\r\n",image_export_directory.Name );
	int FOA=RVAToFOA(vec,image_export_directory.Name);
	s+=GetNameFromFileOffset(filebuffer,filelen,FOA);
	s+=TEXT("\r\n");

	s+=TEXT("DWORD    Base\r\n");
	wsprintf(buf,L"0x%x\r\n",image_export_directory.Base);
	s+=buf;

	s+=TEXT("DWORD    NumberOfFunctions\r\n");
	wsprintf(buf,L"0x%x\r\n",image_export_directory.NumberOfFunctions);
	s+=buf;

	s+=TEXT("DWORD    NumberOfNames\r\n");
	wsprintf(buf,L"0x%x\r\n",image_export_directory.NumberOfNames);
	s+=buf;

	s+=TEXT("DWORD    AddressOfFunctions\r\n");
	wsprintf(buf,L"0x%x\r\n",image_export_directory.AddressOfFunctions);
	s+=buf;

	s+=TEXT("DWORD    AddressOfNames\r\n");
	wsprintf(buf,L"0x%x\r\n",image_export_directory.AddressOfNames);
	s+=buf;

	s+=TEXT("DWORD    AddressOfNameOrdinals\r\n");
	wsprintf(buf,L"0x%x\r\n",image_export_directory.AddressOfNameOrdinals);
	s+=buf;
	s+=TEXT("scanning for functions in this table...\r\n");

	int AddressOfFunctionsFOA=RVAToFOA(vec,image_export_directory.AddressOfFunctions);
	int AddressOfNamesFOA=RVAToFOA(vec,image_export_directory.AddressOfNames);
	int AddressOfNameOrdinalsFOA=RVAToFOA(vec,image_export_directory.AddressOfNameOrdinals);



	int* pfunction_addresses=(int*)(filebuffer+AddressOfFunctionsFOA);
	int* pfunction_names_table=(int*)(filebuffer+AddressOfNamesFOA);
	std::map<std::wstring,short> name_to_ordinal_map;
	std::map<int,int>ordinal_to_RVA_map;
	std::map<short,std::wstring> ordinal_to_name_map;
	for(int i=0;i<image_export_directory.NumberOfNames;i++)
	{
		
		std::wstring function_name=GetNameFromRVA(filebuffer,filelen,vec,pfunction_names_table[i]);
		short function_ordinal=*(short*)(filebuffer+AddressOfNameOrdinalsFOA+2*i);
		name_to_ordinal_map[function_name]=function_ordinal;
	}
	for(auto entry:name_to_ordinal_map)
		ordinal_to_name_map[entry.second]=entry.first;
	for(short i=0;i<image_export_directory.NumberOfFunctions;i++){
		int function_RVA=*(int*)(filebuffer+AddressOfFunctionsFOA+4*i);
		if(ordinal_to_name_map.find(i)!=ordinal_to_name_map.end())
			wsprintf(buf,L"ordinal = %d,name = %s,RVA = 0x%x\r\n",i,ordinal_to_name_map[i].c_str(),function_RVA);
		else wsprintf(buf,L"ordinal = %d,RVA = 0x%x\r\n",i+image_export_directory.Base,function_RVA);
		s+=buf;
	}

	return s;
}

std::wstring CollectInformationFromIMAGE_IMPORT_DESCRIPTOR (char* filebuffer,unsigned int filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_IMPORT_DESCRIPTOR image_import_descriptor){
	wchar_t buf[256];
	size_t convertedChars=0;
	
	std::wstring s=TEXT("");
	s+=TEXT("union\r\n{DWORD Characteristics;DWORD OriginalFirstThunk};\r\n//INT(Import Name Table) address (RVA)\r\n");
	wsprintf(buf,L"0x%x\r\n",image_import_descriptor.OriginalFirstThunk);
	s+=buf;

	s+=TEXT("DWORD TimeDateStamp\r\n");
	wsprintf(buf,L"0x%x\r\n",image_import_descriptor.TimeDateStamp);
	s+=buf;

	s+=TEXT("DWORD ForwarderChain\r\n");
	wsprintf(buf,L"0x%x\r\n",image_import_descriptor.ForwarderChain);
	s+=buf;

	s+=TEXT("DWORD Name\r\n");
	wsprintf(buf,L"0x%x %s\r\n",
		image_import_descriptor.Name,GetNameFromRVA(filebuffer,filelen,vec,image_import_descriptor.Name).c_str());
	
	s+=buf;

	s+=TEXT("DWORD FirstThunk\r\n");
	wsprintf(buf,L"0x%x\r\n",image_import_descriptor.FirstThunk);
	s+=buf;

	s+=TEXT("Collect Information from IAT...\r\n");
	std::vector<IMAGE_THUNK_DATA> image_thunk_data_vector;
	IMAGE_THUNK_DATA image_thunk_data_zero;
	image_thunk_data_zero.u1.AddressOfData=0;
	IMAGE_THUNK_DATA* pimage_thunk_data=(IMAGE_THUNK_DATA*)(filebuffer+RVAToFOA(vec,image_import_descriptor.FirstThunk));
	while(*pimage_thunk_data!=image_thunk_data_zero){
		image_thunk_data_vector.push_back(*pimage_thunk_data);
		pimage_thunk_data++;
	}
	wsprintf(buf,L"count of import functions: %d\r\n",image_thunk_data_vector.size());
	s+=buf;
	for(int i=0;i<image_thunk_data_vector.size();i++){
		if(image_thunk_data_vector[i].u1.Ordinal&IMAGE_ORDINAL_FLAG32)
			wsprintf(buf,L"ordinal = %d",image_thunk_data_vector[i].u1.Ordinal^IMAGE_ORDINAL_FLAG32);
		else {
			ULONGLONG RVA=image_thunk_data_vector[i].u1.AddressOfData;
			int FOA=RVAToFOA(vec,RVA);
			IMAGE_IMPORT_BY_NAME* pimage_import_by_name=
				(IMAGE_IMPORT_BY_NAME*)(filebuffer+FOA);
			std::wstring s=MultiCharToWideString(pimage_import_by_name->Name);
			wsprintf(buf,L"Hint= 0x%04x name = %s \r\n",pimage_import_by_name->Hint,s.c_str());			
			}
		s+=buf;
	}
	return s;
}
std::wstring GetNameFromFileOffset(char* filebuffer,unsigned int filelen,unsigned int FOA){
		if(FOA>=filelen)return TEXT("");
		unsigned int len=strlen(filebuffer+FOA);
		const char* str=filebuffer+FOA;
		if(FOA+len>=filelen)return TEXT("");
		size_t convertedChars=-1;
		wchar_t buf[256];
		mbstowcs_s(&convertedChars,buf,sizeof(buf)/sizeof(wchar_t)-1,(const char*)(filebuffer+FOA),_TRUNCATE);
		std::wstring s=buf;
		
		return s;
	}
std::wstring GetNameFromRVA(char* filebuffer,unsigned int filelen,std::vector<IMAGE_SECTION_HEADER>&vec,unsigned int RVA){
	int FOA=RVAToFOA(vec,RVA);
	return GetNameFromFileOffset(filebuffer,filelen,FOA);
}
std::wstring MultiCharToWideString(const char* str){
	wchar_t buf[256];
	size_t convertedChars=-1;
	mbstowcs_s(&convertedChars,buf,sizeof(buf)/sizeof(wchar_t)-1,str,_TRUNCATE);
	return buf;
}
int RVAToFOA(std::vector<IMAGE_SECTION_HEADER>&vec,unsigned int RVA){
		for(int i=0;i<vec.size();i++)
			if(vec[i].VirtualAddress<=RVA&&RVA<=vec[i].VirtualAddress+vec[i].SizeOfRawData)
			{
				//RVA-vec[i].VirtualAddress==FOA-vec[i].PointerToRawData
				return RVA-vec[i].VirtualAddress+vec[i].PointerToRawData;
			}
			return -1;
	}