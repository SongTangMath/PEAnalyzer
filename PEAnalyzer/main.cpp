#include <windows.h>
#include <WinTrust.h>
#include "resource.h"
#include <string>
#include <vector>
#include <map>
LRESULT CALLBACK WndProc (HWND, UINT, WPARAM, LPARAM);

int AnalyzePEFile(char* filebuffer,size_t filelen,IMAGE_DOS_HEADER* pimage_dos_header,IMAGE_NT_HEADERS* pimage_nt_headers,
				  std::vector<IMAGE_SECTION_HEADER>&vec);
std::wstring CollectInformationFromIMAGE_DOS_HEADER(IMAGE_DOS_HEADER image_dos_header);
std::wstring CollectInformationFromIMAGE_NT_HEADERS(IMAGE_NT_HEADERS image_nt_headers);
std::wstring CollectInformationFromIMAGE_SECTION_HEADER(IMAGE_SECTION_HEADER image_section_header);
std::wstring CollectInformationFromIMAGE_DATA_DIRECTORY(char* filebuffer,size_t filelen,
			IMAGE_DATA_DIRECTORY* pimage_data_directory,std::vector<IMAGE_SECTION_HEADER>&vec);
std::wstring CollectInformationFromIMAGE_EXPORT_DIRECTORY(char* filebuffer,size_t filelen,
	std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_EXPORT_DIRECTORY image_export_directory);
std::wstring CollectInformationFromIMAGE_IMPORT_DESCRIPTOR (char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_IMPORT_DESCRIPTOR image_import_descriptor);
std::wstring CollectInformationFromIMAGE_RESOURCE_DIRECTORY(char* filebuffer,size_t filelen,
	std::vector<IMAGE_SECTION_HEADER>&vec ,IMAGE_RESOURCE_DIRECTORY * poriginal,IMAGE_RESOURCE_DIRECTORY* pcurrent,WORD layer_index);
std::wstring CollectInformationFromIMAGE_RUNTIME_FUNCTION_ENTRY (char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_RUNTIME_FUNCTION_ENTRY image_runtime_function_entry);
std::wstring CollectInformationFromWIN_CERTIFICATE (char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,WIN_CERTIFICATE win_certificate);
std::wstring CollectInformationFromIMAGE_BASE_RELOCATION (char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_BASE_RELOCATION* pimage_base_relocation);
std::wstring CollectInformationFromIMAGE_DEBUG_DIRECTORY (char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_DEBUG_DIRECTORY* pimage_debug_directory);

std::wstring CollectInformationFromIMAGE_ARCHITECTURE_HEADER (char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_ARCHITECTURE_HEADER* pimage_architecture_header);
std::wstring CollectInformationFromIMAGE_TLS_DIRECTORY (char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_TLS_DIRECTORY* pimage_tls_directory);

std::wstring CollectInformationFromIMAGE_LOAD_CONFIG_DIRECTORY(char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_LOAD_CONFIG_DIRECTORY* pimage_load_config_directory);

std::wstring CollectInformationFromIMAGE_BOUND_IMPORT_DESCRIPTOR(char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_BOUND_IMPORT_DESCRIPTOR* pimage_bound_descriptor);
std::wstring CollectInformationFromIMAGE_DELAYLOAD_DESCRIPTOR(char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_DELAYLOAD_DESCRIPTOR* pimage_delayload_descriptor);

std::wstring CollectInformationFromIMAGE_COR20_HEADER(char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_COR20_HEADER* pimage_cor20_header);

std::wstring GetNameFromFileOffset(char* filebuffer,size_t filelen,size_t offset);
std::wstring MultiCharToWideString(const char* str);
std::wstring GetNameFromRVA(char* filebuffer,size_t filelen,std::vector<IMAGE_SECTION_HEADER>&vec,size_t RVA);
std::wstring GetResourceTypeNameById(WORD id);
std::wstring GetIMAGE_FILE_HEADER_Machine_Name(int data);
std::wstring GetIMAGE_FILE_HEADER_Characterstric_Info(int data);
std::wstring GetIMAGE_OPTIONAL_HEADER_Magic_Name(int data);
std::wstring GetIMAGE_OPTIONAL_HEADER_Subsystem_Name(int data);
std::wstring GetIMAGE_OPTIONAL_HEADER_DllCharacteristics_Info(int data);
std::wstring GetIMAGE_SECTION_HEADER_Characteristics_Info(int data);
std::wstring GetIMAGE_IMAGE_DEBUG_DIRECTORY_Type_Name(int data);
size_t RVAToFOA(std::vector<IMAGE_SECTION_HEADER>&vec,size_t RVA);
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
			DWORD fileLengthArray[2];
			fileLengthArray[0]=GetFileSize(hfile,&fileLengthArray[1]);
			size_t filelen=*(size_t*)fileLengthArray;
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

int AnalyzePEFile(char* filebuffer,size_t filelen,IMAGE_DOS_HEADER* pimage_dos_header,
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
	wchar_t buf[256];
	std::wstring s=TEXT("DWORD Signature , 00004550h\r\n");
	wsprintf(buf,L"0x%x\r\n",image_nt_headers.Signature);
	s+=buf;
	s+=TEXT("下面是IMAGE_FILE_HEADER部分\r\n");

	s+=TEXT("WORD  Machine \r\n");
	wsprintf(buf,L"0x%x ",image_nt_headers.FileHeader.Machine);
	s+=buf;
	s+=GetIMAGE_FILE_HEADER_Machine_Name(image_nt_headers.FileHeader.Machine);
	s+=TEXT("\r\n");

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
	wsprintf(buf,L"0x%x ",image_nt_headers.FileHeader.Characteristics);
	s+=buf;
	s+=GetIMAGE_FILE_HEADER_Characterstric_Info(image_nt_headers.FileHeader.Characteristics);
	s+=TEXT("\r\n");

	s+=TEXT("the following is IMAGE_OPTIONAL_HEADER64\r\n");
	s+=TEXT("WORD                 Magic\r\n");
	wsprintf(buf,L"0x%x ",image_nt_headers.OptionalHeader.Magic);
	s+=buf;
	s+=GetIMAGE_OPTIONAL_HEADER_Magic_Name(image_nt_headers.OptionalHeader.Magic);
	s+=TEXT("\r\n");

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
	wsprintf(buf,L"0x%x ",image_nt_headers.OptionalHeader.Subsystem);
	s+=buf;
	s+=GetIMAGE_OPTIONAL_HEADER_Subsystem_Name(image_nt_headers.OptionalHeader.Subsystem);
	s+=TEXT("\r\n");

	s+=TEXT("WORD                 DllCharacteristics;\r\n");
	wsprintf(buf,L"0x%x ",image_nt_headers.OptionalHeader.DllCharacteristics);
	s+=buf;
	s+=GetIMAGE_OPTIONAL_HEADER_DllCharacteristics_Info(image_nt_headers.OptionalHeader.DllCharacteristics);
	s+=TEXT("\r\n");

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

	wsprintf(buf,TEXT("IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES=%d];\r\n\r\n"),
		IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
	s+=buf;
	

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
	wchar_t buf[256];
	std::wstring s=TEXT("BYTE  Name[IMAGE_SIZEOF_SHORT_NAME=8];\r\n");	
	size_t convertedChars=0;	
	mbstowcs_s(&convertedChars,buf,IMAGE_SIZEOF_SHORT_NAME,(const char*)image_section_header.Name,_TRUNCATE);
	
	s+=buf;
	s+=TEXT("\r\n");

	s+=TEXT("union {DWORD PhysicalAddress; DWORD VirtualSize;} Misc\r\n");
	wsprintf(buf,L"0x%x\r\n",image_section_header.Misc.PhysicalAddress);
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
	s+=GetIMAGE_SECTION_HEADER_Characteristics_Info(image_section_header.Characteristics);
	

	return s;
}

std::wstring CollectInformationFromIMAGE_DATA_DIRECTORY(char* filebuffer,size_t filelen,
	IMAGE_DATA_DIRECTORY* pimage_data_directory,std::vector<IMAGE_SECTION_HEADER>&vec){
	
	ULONGLONG FOA=0;
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
	else s+=TEXT("no IMAGE_EXPORT_DIRECTORY=0 found in this image\r\n");
	s+=TEXT("\r\n");


	if(pimage_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress){
		s+=TEXT("image_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT=1]导入表\r\n");
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
	else s+=TEXT("no IMAGE_IMPORT_DESCRIPTOR=1 found in this image\r\n");
	s+=TEXT("\r\n");

	if(pimage_data_directory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress){
		s+=TEXT("image_data_directory[IMAGE_DIRECTORY_ENTRY_RESOURCE=2]资源表\r\n");
		FOA=RVAToFOA(vec,pimage_data_directory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
	IMAGE_RESOURCE_DIRECTORY* poriginal=(IMAGE_RESOURCE_DIRECTORY*)(filebuffer+FOA);
	s+=CollectInformationFromIMAGE_RESOURCE_DIRECTORY(filebuffer,filelen,vec,poriginal,poriginal,0);	
	}
	else s+=TEXT("no IMAGE_RESOURCE_DIRECTORY=2 found in this image\r\n");
	s+=TEXT("\r\n");

	if(pimage_data_directory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress){
	s+=TEXT("image_data_directory[IMAGE_DIRECTORY_ENTRY_EXCEPTION=3]异常表\r\n");
		FOA=RVAToFOA(vec,pimage_data_directory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
		IMAGE_RUNTIME_FUNCTION_ENTRY image_runtime_function_entry=*(IMAGE_RUNTIME_FUNCTION_ENTRY*)(filebuffer+FOA);
		s+=CollectInformationFromIMAGE_RUNTIME_FUNCTION_ENTRY (filebuffer, filelen,
	vec, image_runtime_function_entry);
	}
	else s+=TEXT("no IMAGE_DIRECTORY_ENTRY_EXCEPTION=3 found in this image\r\n");
	s+=TEXT("\r\n");

	if(pimage_data_directory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress){
	s+=TEXT("image_data_directory[IMAGE_DIRECTORY_ENTRY_SECURITY=4]数字签名表\r\n");
		FOA=RVAToFOA(vec,pimage_data_directory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress);
		WIN_CERTIFICATE win_certificate=*(WIN_CERTIFICATE*)(filebuffer+FOA);
		s+=CollectInformationFromWIN_CERTIFICATE (filebuffer, filelen,
	vec, win_certificate);
	}
	else s+=TEXT("no IMAGE_DIRECTORY_ENTRY_SECURITY=4 found in this image\r\n");
	s+=TEXT("\r\n");

	if(pimage_data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress){
	s+=TEXT("image_data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC=5]基址重定位表\r\n");
	
		FOA=RVAToFOA(vec,pimage_data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		IMAGE_BASE_RELOCATION *pimage_base_relocation=(IMAGE_BASE_RELOCATION*)(filebuffer+FOA);
		s+=CollectInformationFromIMAGE_BASE_RELOCATION (filebuffer, filelen,
			vec, pimage_base_relocation);
	}
	else s+=TEXT("no IMAGE_DIRECTORY_ENTRY_BASERELOC=5 found in this image\r\n");
	s+=TEXT("\r\n");

	if(pimage_data_directory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress){
	s+=TEXT("image_data_directory[IMAGE_DIRECTORY_ENTRY_DEBUG=6]调试信息表\r\n");
		FOA=RVAToFOA(vec,pimage_data_directory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
		IMAGE_DEBUG_DIRECTORY* pimage_debug_directory=(IMAGE_DEBUG_DIRECTORY*)(filebuffer+FOA);
		s+=CollectInformationFromIMAGE_DEBUG_DIRECTORY ( filebuffer, filelen,
			vec,pimage_debug_directory);
	}
	else s+=TEXT("no IMAGE_DIRECTORY_ENTRY_DEBUG found=6 in this image\r\n");
	s+=TEXT("\r\n");

	if(pimage_data_directory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress){
	s+=TEXT("image_data_directory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE=7]版权信息表\r\n");
		FOA=RVAToFOA(vec,pimage_data_directory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress);
	}
	else s+=TEXT("no IMAGE_DIRECTORY_ENTRY_ARCHITECTURE=7 found in this image\r\n");
	s+=TEXT("\r\n");

	if(pimage_data_directory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress){
	s+=TEXT("image_data_directory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR=8]全局指针表\r\n");
		FOA=RVAToFOA(vec,pimage_data_directory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress);
	}
	else s+=TEXT("no IMAGE_DIRECTORY_ENTRY_GLOBALPTR=8 found in this image\r\n");
	s+=TEXT("\r\n");

	if(pimage_data_directory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress){
	s+=TEXT("image_data_directory[IMAGE_DIRECTORY_ENTRY_TLS=9]Thread Local Storage线程局部存储表\r\n");
		FOA=RVAToFOA(vec,pimage_data_directory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		IMAGE_TLS_DIRECTORY* pimage_tls_directory=(IMAGE_TLS_DIRECTORY*)(filebuffer+FOA);
		s+= CollectInformationFromIMAGE_TLS_DIRECTORY (filebuffer, filelen,
			vec, pimage_tls_directory);
	}
	else s+=TEXT("no IMAGE_DIRECTORY_ENTRY_TLS=9 found in this image\r\n");
	s+=TEXT("\r\n");

	if(pimage_data_directory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress){
	s+=TEXT("image_data_directory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG=10]加载配置表\r\n");
		FOA=RVAToFOA(vec,pimage_data_directory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
		IMAGE_LOAD_CONFIG_DIRECTORY* pimage_load_config_directory=(IMAGE_LOAD_CONFIG_DIRECTORY*)(filebuffer+FOA);
		s+=CollectInformationFromIMAGE_LOAD_CONFIG_DIRECTORY( filebuffer, filelen,
			vec, pimage_load_config_directory);
	}
	else s+=TEXT("no IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG=10 found in this image\r\n");
	s+=TEXT("\r\n");

	if(pimage_data_directory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress){
	s+=TEXT("image_data_directory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT=11]绑定导入表\r\n");
		FOA=RVAToFOA(vec,pimage_data_directory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress);
		IMAGE_BOUND_IMPORT_DESCRIPTOR* pimage_load_config_directory=(IMAGE_BOUND_IMPORT_DESCRIPTOR*)(filebuffer+FOA);
		s+= CollectInformationFromIMAGE_BOUND_IMPORT_DESCRIPTOR(filebuffer, filelen,
			vec, pimage_load_config_directory);
	}
	else s+=TEXT("no IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT=11 found in this image\r\n");
	s+=TEXT("\r\n");

	if(pimage_data_directory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress){
	s+=TEXT("image_data_directory[IMAGE_DIRECTORY_ENTRY_IAT=12]导入地址表\r\n");
		FOA=RVAToFOA(vec,pimage_data_directory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
	}
	else s+=TEXT("no IMAGE_DIRECTORY_ENTRY_IAT=12 found in this image\r\n");
	s+=TEXT("\r\n");

	if(pimage_data_directory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress){
	s+=TEXT("image_data_directory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT=13]延迟加载表\r\n");
		FOA=RVAToFOA(vec,pimage_data_directory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
		IMAGE_DELAYLOAD_DESCRIPTOR* pimage_delayload_descriptor=(IMAGE_DELAYLOAD_DESCRIPTOR*)(filebuffer+FOA);
		s+=CollectInformationFromIMAGE_DELAYLOAD_DESCRIPTOR(filebuffer, filelen,
			vec, pimage_delayload_descriptor);
	}
	else s+=TEXT("no IMAGE_DIRECTORY_ENTRY_IAT=13 found in this image\r\n");
	s+=TEXT("\r\n");


	if(pimage_data_directory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress){
	s+=TEXT("image_data_directory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR=14]COM Runtime descriptor表\r\n");
		FOA=RVAToFOA(vec,pimage_data_directory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress);
		IMAGE_COR20_HEADER* pimage_cor20_header=(IMAGE_COR20_HEADER*)(filebuffer+FOA);
		s+=CollectInformationFromIMAGE_COR20_HEADER( filebuffer, filelen,
			vec, pimage_cor20_header);
	}
	else s+=TEXT("no IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR=14 found in this image\r\n");
	s+=TEXT("\r\n");

	return s;
	}
std::wstring CollectInformationFromIMAGE_EXPORT_DIRECTORY(char* filebuffer,size_t filelen,
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
	ULONGLONG FOA=RVAToFOA(vec,image_export_directory.Name);
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

	ULONGLONG AddressOfFunctionsFOA=RVAToFOA(vec,image_export_directory.AddressOfFunctions);
	ULONGLONG AddressOfNamesFOA=RVAToFOA(vec,image_export_directory.AddressOfNames);
	ULONGLONG AddressOfNameOrdinalsFOA=RVAToFOA(vec,image_export_directory.AddressOfNameOrdinals);



	int* pfunction_addresses=(int*)(filebuffer+AddressOfFunctionsFOA);
	int* pfunction_names_table=(int*)(filebuffer+AddressOfNamesFOA);
	std::map<std::wstring,short> name_to_ordinal_map;
	std::map<int,int>ordinal_to_RVA_map;
	std::map<WORD,std::wstring> ordinal_to_name_map;
	for(DWORD i=0;i<image_export_directory.NumberOfNames;i++)
	{
		
		std::wstring function_name=GetNameFromRVA(filebuffer,filelen,vec,pfunction_names_table[i]);
		WORD function_ordinal=*(WORD*)(filebuffer+AddressOfNameOrdinalsFOA+2*i);
		name_to_ordinal_map[function_name]=function_ordinal;
	}
	for(auto entry:name_to_ordinal_map)
		ordinal_to_name_map[entry.second]=entry.first;
	for(DWORD i=0;i<image_export_directory.NumberOfFunctions;i++){
		int function_RVA=*(int*)(filebuffer+AddressOfFunctionsFOA+4*i);
		if(ordinal_to_name_map.find(i)!=ordinal_to_name_map.end())
			wsprintf(buf,L"ordinal = %d,name = %s,RVA = 0x%x\r\n",i,ordinal_to_name_map[i].c_str(),function_RVA);
		else wsprintf(buf,L"ordinal = %d,RVA = 0x%x\r\n",i+image_export_directory.Base,function_RVA);
		s+=buf;
	}

	return s;
}

std::wstring CollectInformationFromIMAGE_IMPORT_DESCRIPTOR (char* filebuffer,size_t filelen,
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
			size_t FOA=RVAToFOA(vec,RVA);
			IMAGE_IMPORT_BY_NAME* pimage_import_by_name=
				(IMAGE_IMPORT_BY_NAME*)(filebuffer+FOA);
			std::wstring s=MultiCharToWideString(pimage_import_by_name->Name);
			wsprintf(buf,L"Hint= 0x%04x name = %s \r\n",pimage_import_by_name->Hint,s.c_str());			
			}
		s+=buf;
	}
	return s;
}
std::wstring CollectInformationFromIMAGE_RESOURCE_DIRECTORY(char* filebuffer,size_t filelen,
	std::vector<IMAGE_SECTION_HEADER>&vec ,IMAGE_RESOURCE_DIRECTORY * poriginal,IMAGE_RESOURCE_DIRECTORY* pcurrent,WORD layer_index){
	wchar_t buf[256];
	size_t convertedChars=0;
	std::wstring s;
	/*
	s+=TEXT("DWORD Characteristics\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_resource_directory->Characteristics);
	s+=buf;

	s+=TEXT("DWORD TimeDateStamp\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_resource_directory->TimeDateStamp);
	s+=buf;

	s+=TEXT("WORD MajorVersion\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_resource_directory->MajorVersion);
	s+=buf;

	s+=TEXT("WORD MinorVersion\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_resource_directory->MinorVersion);
	s+=buf;
	*/
	wsprintf(buf,L"layer_index= %d\r\n",layer_index);
	s+=buf;
	s+=TEXT("WORD NumberOfNamedEntries\r\n");
	wsprintf(buf,L"0x%x\r\n",pcurrent->NumberOfNamedEntries);
	s+=buf;

	s+=TEXT("WORD NumberOfIdEntries\r\n");
	wsprintf(buf,L"0x%x\r\n",pcurrent->NumberOfIdEntries);
	s+=buf;

	char* IMAGE_RESOURCE_DIRECTORY_ENTRY_start_point=
		(char*)(pcurrent+1);
	for(WORD index=0;index<pcurrent->NumberOfNamedEntries+pcurrent->NumberOfIdEntries;index++){
	IMAGE_RESOURCE_DIRECTORY_ENTRY *IMAGE_RESOURCE_DIRECTORY_ENTRY_pcurrent=
		(IMAGE_RESOURCE_DIRECTORY_ENTRY*)(IMAGE_RESOURCE_DIRECTORY_ENTRY_start_point+index*sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));

	if(IMAGE_RESOURCE_DIRECTORY_ENTRY_pcurrent->NameIsString){
		IMAGE_RESOURCE_DIR_STRING_U* resource_name=
			(IMAGE_RESOURCE_DIR_STRING_U*)((char*)poriginal+IMAGE_RESOURCE_DIRECTORY_ENTRY_pcurrent->NameOffset);
		wchar_t* name_string=new wchar_t[resource_name->Length+1];
		//size_t temp=wcslen(resource_name->NameString);
		memset(name_string,0,(resource_name->Length+1)*sizeof(wchar_t));
		memcpy(name_string,resource_name->NameString,sizeof(wchar_t)*resource_name->Length);
		s+=TEXT("resource name ");
		s+=name_string;
		delete[]name_string;

	}
	else {
		if(layer_index==0)
		s+=GetResourceTypeNameById(IMAGE_RESOURCE_DIRECTORY_ENTRY_pcurrent->Id);
		else if(layer_index==1){
			wsprintf(buf,TEXT("resource id=0x%d"),IMAGE_RESOURCE_DIRECTORY_ENTRY_pcurrent->Id);
		s+=buf;}
	}
	s+=TEXT("\r\n");
	if(IMAGE_RESOURCE_DIRECTORY_ENTRY_pcurrent->DataIsDirectory){
		IMAGE_RESOURCE_DIRECTORY* pnext_level=(IMAGE_RESOURCE_DIRECTORY*)
			((char*)poriginal+IMAGE_RESOURCE_DIRECTORY_ENTRY_pcurrent->OffsetToDirectory);
		s+=CollectInformationFromIMAGE_RESOURCE_DIRECTORY(filebuffer,filelen,vec,poriginal,pnext_level,layer_index+1);
	}
	else{
	IMAGE_RESOURCE_DATA_ENTRY* pdata_entry=(IMAGE_RESOURCE_DATA_ENTRY*)((char*)poriginal+IMAGE_RESOURCE_DIRECTORY_ENTRY_pcurrent->OffsetToDirectory);
	s+=TEXT("DWORD   OffsetToData\r\n");
	wsprintf(buf,L"0x%x\r\n",pdata_entry->OffsetToData);
	s+=buf;

	s+=TEXT("DWORD   Size\r\n");
	wsprintf(buf,L"0x%x\r\n",pdata_entry->Size);
	s+=buf;

	s+=TEXT("DWORD   CodePage\r\n");
	wsprintf(buf,L"0x%x\r\n",pdata_entry->CodePage);
	s+=buf;

	s+=TEXT("DWORD   Reserved\r\n");
	wsprintf(buf,L"0x%x\r\n",pdata_entry->Reserved);
	s+=buf;
	}
	
	}
	
	return s;
}
std::wstring CollectInformationFromIMAGE_RUNTIME_FUNCTION_ENTRY (char* filebuffer,size_t filelen,
	std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_RUNTIME_FUNCTION_ENTRY image_ia64_runtime_function_entry){
		wchar_t buf[256];
	size_t convertedChars=0;
	std::wstring s;

	s+=TEXT("DWORD   BeginAddress\r\n");
	wsprintf(buf,L"0x%x\r\n",image_ia64_runtime_function_entry.BeginAddress);
	s+=buf;

	s+=TEXT("DWORD   EndAddress\r\n");
	wsprintf(buf,L"0x%x\r\n",image_ia64_runtime_function_entry.EndAddress);
	s+=buf;

	s+=TEXT("DWORD   UnwindInfoAddress\r\n");
	wsprintf(buf,L"0x%x\r\n",image_ia64_runtime_function_entry.UnwindInfoAddress);
	s+=buf;

	size_t  BeginAddressFOA=RVAToFOA(vec,image_ia64_runtime_function_entry.BeginAddress);
	size_t  EndAddressFOA=RVAToFOA(vec,image_ia64_runtime_function_entry.EndAddress);
	size_t  UnwindInfoAddressFOA=RVAToFOA(vec,image_ia64_runtime_function_entry.UnwindInfoAddress);
	//UNWIND_INFO* punwind_info=(UNWIND_INFO*)(filebuffer+UnwindInfoAddressFOA);
	return s;
}
std::wstring CollectInformationFromWIN_CERTIFICATE (char* filebuffer,size_t filelen,
	std::vector<IMAGE_SECTION_HEADER>&vec,WIN_CERTIFICATE win_certificate){
			wchar_t buf[256];
	size_t convertedChars=0;
	std::wstring s;

	s+=TEXT("DWORD   dwLength\r\n");
	wsprintf(buf,L"0x%x\r\n",win_certificate.dwLength);
	s+=buf;

	s+=TEXT("WORD   wRevision\r\n");
	wsprintf(buf,L"0x%x\r\n",win_certificate.wRevision);
	s+=buf;

	s+=TEXT("WORD   wCertificateType\r\n");
	wsprintf(buf,L"0x%x\r\n",win_certificate.wCertificateType);
	s+=buf;

	s+=TEXT("BYTE   bCertificate\r\n");
	wsprintf(buf,L"0x%x\r\n",win_certificate.bCertificate[0]);
	s+=buf;
	return s;
}

std::wstring CollectInformationFromIMAGE_BASE_RELOCATION (char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_BASE_RELOCATION* pimage_base_relocation){
wchar_t buf[256];
	size_t convertedChars=0;
	std::wstring s;
	
	IMAGE_BASE_RELOCATION* pimage_base_relocation_current=pimage_base_relocation;
	while(pimage_base_relocation_current->VirtualAddress){
	s+=TEXT("DWORD   VirtualAddress\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_base_relocation_current->VirtualAddress);
	s+=buf;

	s+=TEXT("DWORD   SizeOfBlock\r\n");
	DWORD num_of_items=(pimage_base_relocation_current->SizeOfBlock-8)/2;
	wsprintf(buf,L"0x%x\r\n",pimage_base_relocation_current->SizeOfBlock);
	s+=buf;
	wsprintf(buf,L"num_of_items= 0x%x\r\n",num_of_items);
	s+=buf;
	
	for(DWORD i=0;i<num_of_items;i++){
	WORD current_item=*(WORD*)((char*)pimage_base_relocation_current+sizeof(IMAGE_BASE_RELOCATION)+2*i);
	if(current_item&0xF000){wsprintf(buf,L"0x%08x\r\n",current_item&0x0FFF+pimage_base_relocation_current->VirtualAddress);s+=buf;}
	else {wsprintf(buf,L"absolute item 0x%08x\r\n",current_item);s+=buf;}
	}
	pimage_base_relocation_current=(IMAGE_BASE_RELOCATION*)((char*)pimage_base_relocation_current+pimage_base_relocation_current->SizeOfBlock);

	s+=TEXT("\r\n");
	}
	return s;
}

std::wstring CollectInformationFromIMAGE_DEBUG_DIRECTORY (char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_DEBUG_DIRECTORY* pimage_debug_directory){
				wchar_t buf[256];
size_t convertedChars=0;
	std::wstring s;
	s+=TEXT("DWORD   Characteristics\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_debug_directory->Characteristics);
	s+=buf;

	s+=TEXT("DWORD   TimeDateStamp\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_debug_directory->TimeDateStamp);
	s+=buf;

	s+=TEXT("WORD   MajorVersion\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_debug_directory->MajorVersion);
	s+=buf;

	s+=TEXT("WORD   MinorVersion\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_debug_directory->MinorVersion);
	s+=buf;

	s+=TEXT("DWORD   Type\r\n");
	wsprintf(buf,L"0x%x %s\r\n",pimage_debug_directory->Type,
		(GetIMAGE_IMAGE_DEBUG_DIRECTORY_Type_Name(pimage_debug_directory->Type)).c_str());
	s+=buf;

	s+=TEXT("DWORD   SizeOfData\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_debug_directory->SizeOfData);
	s+=buf;

	s+=TEXT("DWORD   AddressOfRawData\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_debug_directory->AddressOfRawData);
	s+=buf;

	s+=TEXT("DWORD   PointerToRawData\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_debug_directory->PointerToRawData);
	s+=buf;

return s;
}

std::wstring CollectInformationFromIMAGE_ARCHITECTURE_HEADER (char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_ARCHITECTURE_HEADER* pimage_architecture_header){
wchar_t buf[256];
size_t convertedChars=0;
	std::wstring s;
	s+=TEXT("unsigned int AmaskValue: 1\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_architecture_header->AmaskValue);
	s+=buf;

	s+=TEXT("unsigned int AmaskShift: 8\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_architecture_header->AmaskShift);
	s+=buf;

	s+=TEXT("DWORD FirstEntryRVA\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_architecture_header->FirstEntryRVA);
	s+=buf;
	return s;

}

std::wstring CollectInformationFromIMAGE_TLS_DIRECTORY (char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_TLS_DIRECTORY* pimage_tls_directory){
wchar_t buf[256];
size_t convertedChars=0;
	std::wstring s;

	s+=TEXT("ULONGLONG StartAddressOfRawData\r\n");
	swprintf(buf,sizeof(buf)/sizeof(wchar_t*)-1,L"0x%llx\r\n",pimage_tls_directory->StartAddressOfRawData);
	s+=buf;

	s+=TEXT("ULONGLONG EndAddressOfRawData\r\n");
	swprintf(buf,sizeof(buf)/sizeof(wchar_t*)-1,L"0x%llx\r\n",pimage_tls_directory->EndAddressOfRawData);
	s+=buf;

	s+=TEXT("ULONGLONG AddressOfIndex\r\n");
	swprintf(buf,sizeof(buf)/sizeof(wchar_t*)-1,L"0x%llx\r\n",pimage_tls_directory->AddressOfIndex);
	s+=buf;

	s+=TEXT("ULONGLONG AddressOfCallBacks\r\n");
	swprintf(buf,sizeof(buf)/sizeof(wchar_t*)-1,L"0x%llx\r\n",pimage_tls_directory->AddressOfCallBacks);
	s+=buf;

	s+=TEXT("DWORD   SizeOfZeroFill\r\n");
	swprintf(buf,sizeof(buf)/sizeof(wchar_t*)-1,L"0x%llx\r\n",pimage_tls_directory->SizeOfZeroFill);
	s+=buf;

	s+=TEXT("DWORD   Characteristics\r\n");
	swprintf(buf,sizeof(buf)/sizeof(wchar_t*)-1,L"0x%llx\r\n",pimage_tls_directory->Characteristics);
	s+=buf;
	return s;
}

std::wstring CollectInformationFromIMAGE_LOAD_CONFIG_DIRECTORY(char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_LOAD_CONFIG_DIRECTORY* pimage_load_config_directory){
wchar_t buf[256];
size_t convertedChars=0;
	std::wstring s;

	s+=TEXT("DWORD      Size\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_load_config_directory->Size);
	s+=buf;

	s+=TEXT("DWORD      TimeDateStamp\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_load_config_directory->TimeDateStamp);
	s+=buf;

	s+=TEXT("WORD      MajorVersion\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_load_config_directory->MajorVersion);
	s+=buf;

	s+=TEXT("WORD      MinorVersion\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_load_config_directory->MinorVersion);
	s+=buf;

	s+=TEXT("DWORD      GlobalFlagsClear\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_load_config_directory->GlobalFlagsClear);
	s+=buf;

	s+=TEXT("DWORD      GlobalFlagsSet\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_load_config_directory->GlobalFlagsSet);
	s+=buf;

	s+=TEXT("DWORD      CriticalSectionDefaultTimeout\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_load_config_directory->CriticalSectionDefaultTimeout);
	s+=buf;

	s+=TEXT("ULONGLONG  DeCommitFreeBlockThreshold\r\n");
	swprintf(buf,sizeof(buf)/sizeof(wchar_t*)-1,L"0x%llx\r\n",pimage_load_config_directory->DeCommitFreeBlockThreshold);
	s+=buf;

	s+=TEXT("ULONGLONG  DeCommitTotalFreeThreshold\r\n");
	swprintf(buf,sizeof(buf)/sizeof(wchar_t*)-1,L"0x%llx\r\n",pimage_load_config_directory->DeCommitTotalFreeThreshold);
	s+=buf;

	s+=TEXT("ULONGLONG  LockPrefixTable\r\n");
	swprintf(buf,sizeof(buf)/sizeof(wchar_t*)-1,L"0x%llx\r\n",pimage_load_config_directory->LockPrefixTable);
	s+=buf;

	s+=TEXT("ULONGLONG  MaximumAllocationSize\r\n");
	swprintf(buf,sizeof(buf)/sizeof(wchar_t*)-1,L"0x%llx\r\n",pimage_load_config_directory->MaximumAllocationSize);
	s+=buf;

	s+=TEXT("ULONGLONG  VirtualMemoryThreshold\r\n");
	swprintf(buf,sizeof(buf)/sizeof(wchar_t*)-1,L"0x%llx\r\n",pimage_load_config_directory->VirtualMemoryThreshold);
	s+=buf;

	s+=TEXT("ULONGLONG  ProcessAffinityMask\r\n");
	swprintf(buf,sizeof(buf)/sizeof(wchar_t*)-1,L"0x%llx\r\n",pimage_load_config_directory->ProcessAffinityMask);
	s+=buf;

	s+=TEXT("DWORD      ProcessHeapFlags\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_load_config_directory->ProcessHeapFlags);
	s+=buf;

	s+=TEXT("WORD      CSDVersion\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_load_config_directory->CSDVersion);
	s+=buf;

	s+=TEXT("WORD      Reserved1\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_load_config_directory->Reserved1);
	s+=buf;

	s+=TEXT("ULONGLONG  EditList\r\n");
	swprintf(buf,sizeof(buf)/sizeof(wchar_t*)-1,L"0x%llx\r\n",pimage_load_config_directory->EditList);
	s+=buf;

	s+=TEXT("ULONGLONG  SecurityCookie\r\n");
	swprintf(buf,sizeof(buf)/sizeof(wchar_t*)-1,L"0x%llx\r\n",pimage_load_config_directory->SecurityCookie);
	s+=buf;

	s+=TEXT("ULONGLONG  SEHandlerTable\r\n");
	swprintf(buf,sizeof(buf)/sizeof(wchar_t*)-1,L"0x%llx\r\n",pimage_load_config_directory->SEHandlerTable);
	s+=buf;

	s+=TEXT("ULONGLONG  SEHandlerCount\r\n");
	swprintf(buf,sizeof(buf)/sizeof(wchar_t*)-1,L"0x%llx\r\n",pimage_load_config_directory->SEHandlerCount);
	s+=buf;
	return s;

}

std::wstring CollectInformationFromIMAGE_BOUND_IMPORT_DESCRIPTOR(char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_BOUND_IMPORT_DESCRIPTOR* pimage_bound_descriptor){
wchar_t buf[256];
size_t convertedChars=0;
	std::wstring s;

	s+=TEXT("DWORD      TimeDateStamp\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_bound_descriptor->TimeDateStamp);
	s+=buf;

	s+=TEXT("WORD      OffsetModuleName\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_bound_descriptor->OffsetModuleName);
	s+=buf;

	s+=GetNameFromRVA(filebuffer,filelen,vec,pimage_bound_descriptor->OffsetModuleName);
	s+=TEXT("\r\n");


	s+=TEXT("WORD      NumberOfModuleForwarderRefs\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_bound_descriptor->NumberOfModuleForwarderRefs);
	s+=buf;

	return s;

}
std::wstring CollectInformationFromIMAGE_DELAYLOAD_DESCRIPTOR(char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_DELAYLOAD_DESCRIPTOR* pimage_delayload_descriptor){
wchar_t buf[256];
size_t convertedChars=0;
	std::wstring s;
	s+=TEXT("DWORD      TimeDateStamp\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_delayload_descriptor->Attributes.AllAttributes);
	s+=buf;

	s+=TEXT("DWORD      DllNameRVA\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_delayload_descriptor->DllNameRVA);
	s+=buf;
	s+=GetNameFromRVA(filebuffer,filelen,vec,pimage_delayload_descriptor->DllNameRVA);
	s+=TEXT("\r\n");

	s+=TEXT("DWORD      ModuleHandleRVA\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_delayload_descriptor->ModuleHandleRVA);
	s+=buf;

	s+=TEXT("DWORD      ImportAddressTableRVA\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_delayload_descriptor->ImportAddressTableRVA);
	s+=buf;

	s+=TEXT("DWORD      ImportNameTableRVA\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_delayload_descriptor->ImportNameTableRVA);
	s+=buf;

	s+=TEXT("DWORD      BoundImportAddressTableRVA\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_delayload_descriptor->BoundImportAddressTableRVA);
	s+=buf;

	s+=TEXT("DWORD      UnloadInformationTableRVA\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_delayload_descriptor->UnloadInformationTableRVA);
	s+=buf;

	s+=TEXT("DWORD      TimeDateStamp\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_delayload_descriptor->TimeDateStamp);
	s+=buf;

	return s;
}
std::wstring CollectInformationFromIMAGE_COR20_HEADER(char* filebuffer,size_t filelen,
			std::vector<IMAGE_SECTION_HEADER>&vec,IMAGE_COR20_HEADER* pimage_cor20_header){

wchar_t buf[256];
size_t convertedChars=0;
std::wstring s;
s+=TEXT("DWORD      cb\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->cb);
	s+=buf;

	s+=TEXT("WORD      MajorRuntimeVersion\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->MajorRuntimeVersion);
	s+=buf;

	s+=TEXT("WORD      MinorRuntimeVersion\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->MinorRuntimeVersion);
	s+=buf;

	s+=TEXT("IMAGE_DATA_DIRECTORY      MetaData.VirtualAddress\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->MetaData.VirtualAddress);

	s+=TEXT("IMAGE_DATA_DIRECTORY      MetaData.Size\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->MetaData.Size);
	s+=buf;

	s+=TEXT("DWORD      Flags\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->Flags);
	s+=buf;

	s+=TEXT("DWORD      EntryPointToken/EntryPointRVA\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->EntryPointRVA);
	s+=buf;

	s+=TEXT("IMAGE_DATA_DIRECTORY      Resources.VirtualAddress\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->Resources.VirtualAddress);

	s+=TEXT("IMAGE_DATA_DIRECTORY      Resources.Size\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->Resources.Size);
	s+=buf;

	s+=TEXT("IMAGE_DATA_DIRECTORY      StrongNameSignature.VirtualAddress\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->StrongNameSignature.VirtualAddress);

	s+=TEXT("IMAGE_DATA_DIRECTORY      StrongNameSignature.Size\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->StrongNameSignature.Size);
	s+=buf;

	s+=TEXT("IMAGE_DATA_DIRECTORY      CodeManagerTable.VirtualAddress\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->CodeManagerTable.VirtualAddress);

	s+=TEXT("IMAGE_DATA_DIRECTORY      CodeManagerTable.Size\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->CodeManagerTable.Size);
	s+=buf;

	s+=TEXT("IMAGE_DATA_DIRECTORY      VTableFixups.VirtualAddress\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->VTableFixups.VirtualAddress);

	s+=TEXT("IMAGE_DATA_DIRECTORY      VTableFixups.Size\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->VTableFixups.Size);
	s+=buf;

	s+=TEXT("IMAGE_DATA_DIRECTORY      ExportAddressTableJumps.VirtualAddress\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->ExportAddressTableJumps.VirtualAddress);

	s+=TEXT("IMAGE_DATA_DIRECTORY      ExportAddressTableJumps.Size\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->ExportAddressTableJumps.Size);
	s+=buf;

	s+=TEXT("IMAGE_DATA_DIRECTORY      ManagedNativeHeader.VirtualAddress\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->ManagedNativeHeader.VirtualAddress);

	s+=TEXT("IMAGE_DATA_DIRECTORY      ManagedNativeHeader.Size\r\n");
	wsprintf(buf,L"0x%x\r\n",pimage_cor20_header->ManagedNativeHeader.Size);
	s+=buf;

	
return s;
}
std::wstring GetNameFromFileOffset(char* filebuffer,size_t filelen,size_t FOA){
		if(FOA>=filelen)return TEXT("");
		size_t len=strlen(filebuffer+FOA);
		const char* str=filebuffer+FOA;
		if(FOA+len>=filelen)return TEXT("");
		size_t convertedChars=0;
		wchar_t buf[256];
		mbstowcs_s(&convertedChars,buf,sizeof(buf)/sizeof(wchar_t)-1,(const char*)(filebuffer+FOA),_TRUNCATE);
		std::wstring s=buf;
		
		return s;
	}
std::wstring GetNameFromRVA(char* filebuffer,size_t filelen,std::vector<IMAGE_SECTION_HEADER>&vec,size_t RVA){
	ULONGLONG FOA=RVAToFOA(vec,RVA);
	return GetNameFromFileOffset(filebuffer,filelen,FOA);
}
std::wstring MultiCharToWideString(const char* str){
	wchar_t buf[256];
	size_t convertedChars=0;
	mbstowcs_s(&convertedChars,buf,sizeof(buf)/sizeof(wchar_t)-1,str,_TRUNCATE);
	return buf;
}
size_t RVAToFOA(std::vector<IMAGE_SECTION_HEADER>&vec,size_t RVA){
		for(size_t i=0;i<vec.size();i++)
			if(vec[i].VirtualAddress<=RVA&&RVA<=vec[i].VirtualAddress+vec[i].SizeOfRawData)
			{
				//RVA-vec[i].VirtualAddress==FOA-vec[i].PointerToRawData
				return RVA-vec[i].VirtualAddress+vec[i].PointerToRawData;
			}
			return 0;
	}
std::wstring GetResourceTypeNameById(WORD id){
	switch(id){
	case 0x01:
			return TEXT("Cursor");			
			case 0x02:
			return TEXT("Bitmap");			
			case 0x03:
			return TEXT("Icon");
			case 0x04:
			return TEXT("Menu");
			case 0x05:
			return TEXT("Dialog");
			case 0x06:
			return TEXT("String");
			case 0x07:
			return TEXT("Font Directory");
			case 0x08:
			return TEXT("Font");
			case 0x09:
			return TEXT("Accelerator");			
			case 0x0a:
			return TEXT("Unformatted");
			case 0x0b:
			return TEXT("MessageTable");			
			case 0x0c:
			return TEXT("Group Cursor");
			case 0x0d:
			return TEXT("Group Icon");
			break;
			case 0x0e:
			return TEXT("Cursor");
			case 0x10:
			return TEXT("Version Information");
			default: {
				wchar_t buf[256];
				wsprintf(buf,TEXT("user defined resource type id=%d"),id);
				return buf;
					 }
		}
}

std::wstring GetIMAGE_FILE_HEADER_Machine_Name(int data){
	switch(data){
	case IMAGE_FILE_MACHINE_I386:return TEXT("IMAGE_FILE_MACHINE_I386 x86");
	case IMAGE_FILE_MACHINE_IA64:return TEXT("IMAGE_FILE_MACHINE_IA64 Intel Itanium");
	case IMAGE_FILE_MACHINE_AMD64:return TEXT("IMAGE_FILE_MACHINE_AMD64 x64");
	default:return TEXT("");
	}
}
std::wstring GetIMAGE_FILE_HEADER_Characterstric_Info(int data){
	std::wstring s=TEXT("\r\n");
	if(data&IMAGE_FILE_RELOCS_STRIPPED)s+=TEXT("IMAGE_FILE_RELOCS_STRIPPED \r\n");
	if(data&IMAGE_FILE_EXECUTABLE_IMAGE)s+=TEXT("IMAGE_FILE_EXECUTABLE_IMAGE \r\n");
	if(data&IMAGE_FILE_LINE_NUMS_STRIPPED)s+=TEXT("IMAGE_FILE_LINE_NUMS_STRIPPED \r\n");
	if(data&IMAGE_FILE_LOCAL_SYMS_STRIPPED)s+=TEXT("IMAGE_FILE_LOCAL_SYMS_STRIPPED \r\n");
	if(data&IMAGE_FILE_AGGRESIVE_WS_TRIM)s+=TEXT("IMAGE_FILE_AGGRESIVE_WS_TRIM \r\n");
	if(data&IMAGE_FILE_LARGE_ADDRESS_AWARE)s+=TEXT("IMAGE_FILE_LARGE_ADDRESS_AWARE \r\n");
	if(data&IMAGE_FILE_BYTES_REVERSED_LO)s+=TEXT("IMAGE_FILE_BYTES_REVERSED_LO \r\n");
	if(data&IMAGE_FILE_32BIT_MACHINE)s+=TEXT("IMAGE_FILE_32BIT_MACHINE \r\n");
	if(data&IMAGE_FILE_DEBUG_STRIPPED)s+=TEXT("IMAGE_FILE_DEBUG_STRIPPED ");
	if(data&IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)s+=TEXT("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP \r\n");
	if(data&IMAGE_FILE_NET_RUN_FROM_SWAP)s+=TEXT("IMAGE_FILE_NET_RUN_FROM_SWAP \r\n");
	if(data&IMAGE_FILE_SYSTEM)s+=TEXT("IMAGE_FILE_SYSTEM \r\n");
	if(data&IMAGE_FILE_DLL)s+=TEXT("IMAGE_FILE_DLL \r\n");
	if(data&IMAGE_FILE_UP_SYSTEM_ONLY)s+=TEXT("IMAGE_FILE_UP_SYSTEM_ONLY \r\n");
	if(data&IMAGE_FILE_BYTES_REVERSED_HI)s+=TEXT("IMAGE_FILE_BYTES_REVERSED_HI \r\n");

	return s;
}

std::wstring GetIMAGE_OPTIONAL_HEADER_Magic_Name(int data){
	switch (data){	
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:return TEXT("IMAGE_NT_OPTIONAL_HDR32_MAGIC");
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:return TEXT("IMAGE_NT_OPTIONAL_HDR64_MAGIC");
	case IMAGE_ROM_OPTIONAL_HDR_MAGIC:return TEXT("IMAGE_ROM_OPTIONAL_HDR_MAGIC");

	default:return TEXT("");
	}
}

std::wstring GetIMAGE_OPTIONAL_HEADER_Subsystem_Name(int data){
	switch (data){	
	case IMAGE_SUBSYSTEM_UNKNOWN:return TEXT("IMAGE_SUBSYSTEM_UNKNOWN");
	case IMAGE_SUBSYSTEM_NATIVE:return TEXT("IMAGE_SUBSYSTEM_NATIVE");
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:return TEXT("IMAGE_SUBSYSTEM_WINDOWS_GUI");
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:return TEXT("IMAGE_SUBSYSTEM_WINDOWS_CUI");
	case IMAGE_SUBSYSTEM_OS2_CUI:return TEXT("IMAGE_SUBSYSTEM_OS2_CUI");
	case IMAGE_SUBSYSTEM_POSIX_CUI:return TEXT("IMAGE_SUBSYSTEM_POSIX_CUI");
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:return TEXT("IMAGE_SUBSYSTEM_WINDOWS_CE_GUI");
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:return TEXT("IMAGE_SUBSYSTEM_EFI_APPLICATION");
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:return TEXT("IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER");
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:return TEXT("IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER");
	case IMAGE_SUBSYSTEM_EFI_ROM:return TEXT("IMAGE_SUBSYSTEM_EFI_ROM");
	case IMAGE_SUBSYSTEM_XBOX:return TEXT("IMAGE_SUBSYSTEM_XBOX");
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:return TEXT("IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION");

	default:return TEXT("");
	}
}

std::wstring GetIMAGE_OPTIONAL_HEADER_DllCharacteristics_Info(int data){
	std::wstring s=TEXT("\r\n");
	if(data&0x0001||data&0x0002||data&0x0004||data&0x0008||data&0x1000||data&0x2000||data&0x4000)
		s+=TEXT("Reserved \r\n");
	if(data&IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)s+=TEXT("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE \r\n");
	if(data&IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)s+=TEXT("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY \r\n");
	if(data&IMAGE_DLLCHARACTERISTICS_NX_COMPAT)s+=TEXT("IMAGE_DLLCHARACTERISTICS_NX_COMPAT \r\n");
	if(data&IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)s+=TEXT("IMAGE_DLLCHARACTERISTICS_NO_ISOLATION \r\n");
	if(data&IMAGE_DLLCHARACTERISTICS_NO_SEH)s+=TEXT("IMAGE_DLLCHARACTERISTICS_NO_SEH \r\n");
	if(data&IMAGE_DLLCHARACTERISTICS_NO_BIND)s+=TEXT("IMAGE_DLLCHARACTERISTICS_NO_BIND \r\n");
	if(data&IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)s+=TEXT("IMAGE_DLLCHARACTERISTICS_WDM_DRIVER \r\n");
	if(data&IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)s+=TEXT("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE \r\n");
	return s;

}
std::wstring GetIMAGE_SECTION_HEADER_Characteristics_Info(int data){
	std::wstring s=TEXT("\r\n");
	if(data&0x0001||data&0x0002||data&0x0004||data&0x0010||data&0x400||data&0x2000||data&0x10000)
		s+=TEXT("Reserved \r\n");
	if(data&IMAGE_SCN_TYPE_NO_PAD)s+=TEXT("IMAGE_SCN_TYPE_NO_PAD \r\n");
	if(data&IMAGE_SCN_CNT_CODE)s+=TEXT("IMAGE_SCN_CNT_CODE \r\n");
	if(data&IMAGE_SCN_CNT_INITIALIZED_DATA)s+=TEXT("IMAGE_SCN_CNT_INITIALIZED_DATA \r\n");
	if(data&IMAGE_SCN_CNT_UNINITIALIZED_DATA)s+=TEXT("IMAGE_SCN_CNT_UNINITIALIZED_DATA \r\n");
	if(data&IMAGE_SCN_LNK_OTHER)s+=TEXT("IMAGE_SCN_LNK_OTHER \r\n");
	if(data&IMAGE_SCN_LNK_INFO)s+=TEXT("IMAGE_SCN_LNK_INFO \r\n");
	if(data&IMAGE_SCN_LNK_REMOVE)s+=TEXT("IMAGE_SCN_LNK_REMOVE \r\n");
	if(data&IMAGE_SCN_LNK_COMDAT)s+=TEXT("IMAGE_SCN_LNK_COMDAT \r\n");

	if(data&IMAGE_SCN_NO_DEFER_SPEC_EXC)s+=TEXT("IMAGE_SCN_NO_DEFER_SPEC_EXC \r\n");
	if(data&IMAGE_SCN_GPREL)s+=TEXT("IMAGE_SCN_GPREL \r\n");
	if(data&IMAGE_SCN_MEM_PURGEABLE)s+=TEXT("IMAGE_SCN_MEM_PURGEABLE \r\n");
	if(data&IMAGE_SCN_MEM_LOCKED)s+=TEXT("IMAGE_SCN_MEM_LOCKED \r\n");
	if(data&IMAGE_SCN_MEM_PRELOAD)s+=TEXT("IMAGE_SCN_MEM_PRELOAD \r\n");
	int flag=0x00F00000;
	switch(data&flag){
	case IMAGE_SCN_ALIGN_1BYTES:s+=TEXT("IMAGE_SCN_ALIGN_1BYTES\r\n");
	case IMAGE_SCN_ALIGN_2BYTES:s+=TEXT("IMAGE_SCN_ALIGN_2BYTES\r\n");
	case IMAGE_SCN_ALIGN_4BYTES:s+=TEXT("IMAGE_SCN_ALIGN_4BYTES\r\n");
	case IMAGE_SCN_ALIGN_8BYTES:s+=TEXT("IMAGE_SCN_ALIGN_8BYTES\r\n");
	case IMAGE_SCN_ALIGN_16BYTES:s+=TEXT("IMAGE_SCN_ALIGN_16BYTES\r\n");
	case IMAGE_SCN_ALIGN_32BYTES:s+=TEXT("IMAGE_SCN_ALIGN_32BYTES\r\n");
	case IMAGE_SCN_ALIGN_64BYTES:s+=TEXT("IMAGE_SCN_ALIGN_64BYTES\r\n");
	case IMAGE_SCN_ALIGN_128BYTES:s+=TEXT("IMAGE_SCN_ALIGN_128BYTES\r\n");
	case IMAGE_SCN_ALIGN_256BYTES:s+=TEXT("IMAGE_SCN_ALIGN_256BYTES\r\n");
	case IMAGE_SCN_ALIGN_512BYTES:s+=TEXT("IMAGE_SCN_ALIGN_512BYTES\r\n");
	case IMAGE_SCN_ALIGN_1024BYTES:s+=TEXT("IMAGE_SCN_ALIGN_1024BYTES\r\n");
	case IMAGE_SCN_ALIGN_2048BYTES:s+=TEXT("IMAGE_SCN_ALIGN_2048BYTES\r\n");
	case IMAGE_SCN_ALIGN_4096BYTES:s+=TEXT("IMAGE_SCN_ALIGN_4096BYTES\r\n");
	case IMAGE_SCN_ALIGN_8192BYTES:s+=TEXT("IMAGE_SCN_ALIGN_8192BYTES\r\n");
	
	}
	if(data&IMAGE_SCN_LNK_NRELOC_OVFL)s+=TEXT("IMAGE_SCN_LNK_NRELOC_OVFL \r\n");
	if(data&IMAGE_SCN_MEM_DISCARDABLE)s+=TEXT("IMAGE_SCN_MEM_DISCARDABLE \r\n");
	if(data&IMAGE_SCN_MEM_NOT_CACHED)s+=TEXT("IMAGE_SCN_MEM_NOT_CACHED \r\n");
	if(data&IMAGE_SCN_MEM_NOT_PAGED)s+=TEXT("IMAGE_SCN_MEM_NOT_PAGED \r\n");
	if(data&IMAGE_SCN_MEM_SHARED)s+=TEXT("IMAGE_SCN_MEM_SHARED \r\n");
	if(data&IMAGE_SCN_MEM_EXECUTE)s+=TEXT("IMAGE_SCN_MEM_EXECUTE \r\n");

	if(data&IMAGE_SCN_MEM_READ)s+=TEXT("IMAGE_SCN_MEM_READ \r\n");
	if(data&IMAGE_SCN_MEM_WRITE)s+=TEXT("IMAGE_SCN_MEM_WRITE \r\n");	
	return s;
}
std::wstring GetIMAGE_IMAGE_DEBUG_DIRECTORY_Type_Name(int data){
	switch(data){
	case IMAGE_DEBUG_TYPE_UNKNOWN :return TEXT("IMAGE_DEBUG_TYPE_UNKNOWN ");
	case IMAGE_DEBUG_TYPE_COFF  :return TEXT("IMAGE_DEBUG_TYPE_COFF  ");
	case IMAGE_DEBUG_TYPE_CODEVIEW  :return TEXT("IMAGE_DEBUG_TYPE_CODEVIEW  ");
	case IMAGE_DEBUG_TYPE_FPO  :return TEXT("IMAGE_DEBUG_TYPE_FPO  ");
	case IMAGE_DEBUG_TYPE_MISC  :return TEXT("IMAGE_DEBUG_TYPE_MISC  ");
	case IMAGE_DEBUG_TYPE_EXCEPTION  :return TEXT("IMAGE_DEBUG_TYPE_EXCEPTION  ");
	case IMAGE_DEBUG_TYPE_FIXUP  :return TEXT("IMAGE_DEBUG_TYPE_FIXUP  ");
	case IMAGE_DEBUG_TYPE_OMAP_TO_SRC  :return TEXT("IMAGE_DEBUG_TYPE_OMAP_TO_SRC  ");

	case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC  :return TEXT("IMAGE_DEBUG_TYPE_OMAP_FROM_SRC  ");
	case IMAGE_DEBUG_TYPE_BORLAND   :return TEXT("IMAGE_DEBUG_TYPE_BORLAND   ");
	case IMAGE_DEBUG_TYPE_RESERVED10   :return TEXT("IMAGE_DEBUG_TYPE_RESERVED10   ");
	case IMAGE_DEBUG_TYPE_CLSID   :return TEXT("IMAGE_DEBUG_TYPE_CLSID   ");
	case 16   :return TEXT("IMAGE_DEBUG_TYPE_REPRO   ");
	case 20  :return TEXT("IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS  ");
	
	default:return TEXT("");
	}

}