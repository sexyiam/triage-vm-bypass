#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <windows.h>
#include <winhttp.h>
#include <Lmcons.h>
#include <iphlpapi.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstdio>  
#include <array> 
#include <fstream>
#include "xorstr.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")

// Component Object Model initialization //
void initializeCOM()
{
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED); // multithreaded
    if (FAILED(hres)) {
        //    << std::hex << hres << std::endl;
        exit(1);
    }
}

// security level initialization for COM initialization //
void initializeSecurity()
{
    HRESULT hres = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );

    if (FAILED(hres)) {
            //<< std::hex << hres << std::endl;
        CoUninitialize();
        exit(1);
    }
}

// create a instance for connect to WMI (windows management instrumentation) //
IWbemLocator* createWbemLocator()
{
    IWbemLocator* pLoc = NULL;
    HRESULT hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres)) {
            //<< std::hex << hres << std::endl;
        CoUninitialize();
        exit(1);
    }

    return pLoc;
}

// connect to WMI (windows management instrumentation) //
IWbemServices* connectWMI(IWbemLocator* pLoc)
{
    IWbemServices* pSvc = NULL;
    HRESULT hres = pLoc->ConnectServer(
        _bstr_t(xorstr_(L"ROOT\\CIMV2")),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );

    if (FAILED(hres)) {
        pLoc->Release();
        // if the connection fails, free the locator and exit
        CoUninitialize();
        exit(1);
    }

    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        exit(1);
    }

    return pSvc;
}

// make an request to the WMI service to get the system information //
void systemInfoPrintXD(IWbemServices* pSvc, const std::wstring& query, const std::wstring& propertyName)
{
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hres = pSvc->ExecQuery(
        bstr_t(xorstr_("WQL")),
        bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
            //<< L"Error code = 0x"
            //<< std::hex << hres << std::endl;
        return;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;
        hr = pclsObj->Get(propertyName.c_str(), 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            std::wcout << propertyName << xorstr_(L" : ") << vtProp.bstrVal << std::endl;
            VariantClear(&vtProp);
        }

        pclsObj->Release();
    }

    pEnumerator->Release();
}

// get the user name //
std::wstring getUserPath()
{
    WCHAR username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    if (GetUserNameW(username, &username_len)) {
        return std::wstring(username);
    }
    else {
        exit(1);
    }
}

// get the mac address //
std::wstring getMAC()
{
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD dwBufLen = sizeof(AdapterInfo);
    DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
    std::wstring macAddr;

    if (dwStatus == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
        while (pAdapterInfo) {
            if (pAdapterInfo->AddressLength == 6) {
                std::wostringstream oss;
                oss << std::hex;
                for (UINT i = 0; i < pAdapterInfo->AddressLength; ++i) {
                    oss << (i == 0 ? xorstr_(L"") : xorstr_(L"-")) << std::setw(2) << std::setfill(L'0') << (int)pAdapterInfo->Address[i];
                }
                macAddr = oss.str();
                break; 
            }
            pAdapterInfo = pAdapterInfo->Next;
        }
    }

    return macAddr;
}

// get the hardware id //
std::wstring getHWID(IWbemServices* pSvc)
{
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hres = pSvc->ExecQuery(
        bstr_t(xorstr_("WQL")),
        bstr_t(xorstr_("SELECT * FROM Win32_ComputerSystemProduct")),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
            //<< L"Error code = 0x"
            //<< std::hex << hres << std::endl;
        return L"";
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    std::wstring hwid;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;
        hr = pclsObj->Get(xorstr_(L"UUID"), 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            hwid = vtProp.bstrVal;
            VariantClear(&vtProp);
        }

        pclsObj->Release();
    }

    pEnumerator->Release();
    return hwid;
}

// execute a background process and return the output //
std::string executePowershellCommand(const std::string& command)
{
    std::array<char, 128> buffer;
    std::string result;
    FILE* pipe = _popen(command.c_str(), xorstr_("r"));
    if (!pipe) {
        return "";
    }
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    _pclose(pipe);
    return result;
}

// get the Hyper-V status //
std::wstring getHyperVstatus()
{
    std::array<char, 128> buffer;
    std::string result;
    FILE* pipe = _popen(xorstr_("systeminfo"), xorstr_("r"));
    if (!pipe) {
        return L"";
    }
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    _pclose(pipe);

    std::istringstream iss(result);
    std::string line;
    bool virtualizationEnabled = false;
    bool depEnabled = false;

    while (std::getline(iss, line)) {
        if (line.find(xorstr_("Hyper-V Requirements:")) != std::string::npos) {
            if (line.find(xorstr_("VM Monitor Mode Extensions: Yes")) != std::string::npos) {
                virtualizationEnabled = true;
            }
            if (line.find(xorstr_("Virtualization Enabled In Firmware: Yes")) != std::string::npos) {
                virtualizationEnabled = true;
            }
            if (line.find(xorstr_("Second Level Address Translation: Yes")) != std::string::npos) {
                depEnabled = true;
            }
            if (line.find(xorstr_("Data Execution Prevention Available: Yes")) != std::string::npos) {
                depEnabled = true;
            }
        }
    }

    if (virtualizationEnabled && depEnabled) {
        return xorstr_(L"Hyper-V is enabled.");
    } else {
        return xorstr_(L"Hyper-V is not enabled.");
    }
}

// check if the drive F: is empty <- triage virtual machines have a drive F: with no files //
void checkUSB()
{
    UINT driveType = GetDriveType(xorstr_(L"F:\\"));
    if (driveType == DRIVE_NO_ROOT_DIR) {
        return;
    }

    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile(xorstr_(L"F:\\*.*"), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        exit(1);
    } else {
        bool isEmpty = true;
        do {
            if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                isEmpty = false;
                break;
            }
        } while (FindNextFile(hFind, &findFileData) != 0);

        FindClose(hFind);

        if (isEmpty) {
            // uwu
            exit(1);
        } else {
        }
    }
}

// check if the manufacturer and model of the system is a known virtual machine combination //
bool checkModelAndManufacturer(IWbemServices* pSvc, const std::vector<std::pair<std::wstring, std::wstring>>& expectedCombinations)
{
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hres = pSvc->ExecQuery(
        bstr_t(xorstr_("WQL")),
        bstr_t(xorstr_("SELECT Manufacturer, Model FROM Win32_ComputerSystem")),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        std::wcerr << xorstr_(L"Query for Manufacturer and Model failed. ")
            << xorstr_(L"Error code = 0x")
            << std::hex << hres << std::endl;
        return false;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    bool match = false;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn) {
            break;
        }

        VARIANT vtManufacturer;
        VARIANT vtModel;

        hr = pclsObj->Get(xorstr_(L"Manufacturer"), 0, &vtManufacturer, 0, 0);
        if (SUCCEEDED(hr)) {
            hr = pclsObj->Get(xorstr_(L"Model"), 0, &vtModel, 0, 0);
            if (SUCCEEDED(hr)) {
                std::wcout << xorstr_(L"Manufacturer: ") << vtManufacturer.bstrVal << std::endl;
                std::wcout << xorstr_(L"Model: ") << vtModel.bstrVal << std::endl;

                for (const auto& combination : expectedCombinations) {
                    if (combination.first == vtManufacturer.bstrVal && combination.second == vtModel.bstrVal) {
                        match = true;
                        break;
                    }
                }
                VariantClear(&vtModel);
            }
            VariantClear(&vtManufacturer);
        }

        pclsObj->Release();
    }

    pEnumerator->Release();
    return match;
}

// main xd lol //
int main()
{
    // initialize COM and security //
    initializeCOM();
    initializeSecurity();

    // create a WMI locator and connect to WMI //
    IWbemLocator* pLoc = createWbemLocator();
    IWbemServices* pSvc = connectWMI(pLoc);

    //std::wcout << L"System Information:" << std::endl;
    //systemInfoPrintXD(pSvc, L"SELECT * FROM Win32_ComputerSystem", L"Manufacturer");
    //systemInfoPrintXD(pSvc, L"SELECT * FROM Win32_ComputerSystem", L"Model");

    // print system information //
    systemInfoPrintXD(pSvc, xorstr_(L"SELECT * FROM Win32_OperatingSystem"), xorstr_(L"Caption"));
    systemInfoPrintXD(pSvc, xorstr_(L"SELECT * FROM Win32_Processor"), xorstr_(L"Name"));
    systemInfoPrintXD(pSvc, xorstr_(L"SELECT * FROM Win32_VideoController"), xorstr_(L"Name"));

    // print more system information //
    std::wcout << xorstr_("Username: ") << getUserPath() << std::endl;
    std::wcout << xorstr_("MAC Address: ") << getMAC() << std::endl;
    std::wcout << xorstr_("HWID: ") << getHWID(pSvc) << std::endl;
    std::wcout << xorstr_("Hyper-V Status: ") << getHyperVstatus() << std::endl;

    // manufaturer and model combinations to check //
    std::vector<std::pair<std::wstring, std::wstring>> combinations = {
        {xorstr_(L"BOCHS_"), xorstr_(L"BXPC___")}, // windows 7, 10, 11
        {xorstr_(L"QEMU"), xorstr_(L"Standard PC (Q35 + ICH9, 2009)")}, // old windows vm triage
        {xorstr_(L"innotek GmbH"), xorstr_(L"VirtualBox")} // extra! virtual box check
    };

    // check if the system is a known virtual machine combination, if so, exit //
    if (checkModelAndManufacturer(pSvc, combinations)) {
        //std::wcout << L"Triage detected!" << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        exit(1);
    }

    // check if the drive F: is empty <- classic triage virtual machines have a drive F: with no files //
    checkUSB();

    // release the COM objects //
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    // sleep for 2 seconds (optional)//
    Sleep(2000);

    // modify files example for generate flags//

    WCHAR currentDirectory[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, currentDirectory);

    std::wstring filePath = std::wstring(currentDirectory) + L"\\flag.txt";

    std::ofstream outFile(filePath);
    outFile << "triage suck my dick" << std::endl;
    outFile.close();

    ShellExecute(NULL, L"open", filePath.c_str(), NULL, NULL, SW_SHOW);

    return 0;
}
