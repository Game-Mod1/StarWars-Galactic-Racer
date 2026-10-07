#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <commctrl.h>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define ID_BTN_ATTACH       1001
#define ID_CHK_HEALTH       1002
#define ID_CHK_BOOST        1003
#define ID_CHK_ENERGY       1004
#define ID_CHK_ABILITYCD    1005
#define ID_CHK_TIMER        1006
#define ID_CHK_NOEXPLODE    1007
#define ID_CHK_AINOBOOST    1008
#define ID_CHK_AINOMOVE     1009
#define ID_CHK_CREDITS      1010
#define ID_BTN_CREDITS      1011
#define ID_EDIT_CREDITS     1012
#define ID_EDIT_SPEED       1013
#define ID_BTN_SPEED        1014
#define ID_STATUS           1015
#define ID_TIMER            2001

HWND g_hwnd = NULL;
HWND g_hStatus = NULL;
HANDLE g_hProcess = NULL;
DWORD g_dwPID = 0;
uintptr_t g_modBase = 0;
size_t g_modSize = 0;

bool g_health = false, g_boost = false, g_energy = false, g_abilitycd = false;
bool g_timer = false, g_noexplode = false, g_ainoboost = false, g_ainomove = false;
bool g_credits = false;

uintptr_t addr_health = 0, addr_boost = 0, addr_abilitycd = 0, addr_timer = 0;
uintptr_t addr_credits = 0, addr_playerpawn = 0, addr_vehicle = 0, addr_campaign = 0;

BYTE pat_health[] = {0x83,0xBF,0x00,0x00,0x00,0x00,0x01,0x7F};
char  msk_health[] = "xx????xx";
BYTE pat_boost[] = {0xF3,0x0F,0x5F,0x00,0xF3,0x0F,0x11,0x86,0x00,0x00,0x00,0x00,0x0F,0x57};
char  msk_boost[] = "xxx?xxxx????xx";
BYTE pat_abilitycd[] = {0xC7,0x81,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xC6};
char  msk_abilitycd[] = "xx????xxxxx";
BYTE pat_timer[] = {0xF2,0x0F,0x5C,0xB6,0x00,0x00,0x00,0x00,0xF2,0x0F,0x11};
char  msk_timer[] = "xxxx????xxx";
BYTE pat_credits[] = {0x48,0x8B,0x81,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x74,0x00,0x8B,0x80,0x4C,0x01,0x00,0x00};
char  msk_credits[] = "xxx????x?x?xxxxxx";
BYTE pat_pawn[] = {0x48,0x3B,0xBE,0x00,0x00,0x00,0x00,0x00,0x0F,0x94};
char  msk_pawn[] = "xxx????xxx";
BYTE pat_vehicle[] = {0x4C,0x8D,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0F,0x28,0x00,0xE8};
char  msk_vehicle[] = "xx?????????xx?x";
BYTE pat_campaign[] = {0x48,0x8B,0x8E,0x00,0x00,0x00,0x00,0xE8,0x00,0x00,0x00,0x00,0x80};
char  msk_campaign[] = "xxx????x????x";

bool MatchPattern(const BYTE* data, const BYTE* pat, const char* mask, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (mask[i] == 'x' && data[i] != pat[i]) return false;
    }
    return true;
}

uintptr_t PatternScan(HANDLE hProc, uintptr_t start, size_t size, const BYTE* pat, const char* mask) {
    size_t plen = strlen(mask);
    const size_t CHUNK = 0x10000;
    std::vector<BYTE> buf(CHUNK + plen);
    for (size_t offset = 0; offset < size; offset += CHUNK) {
        size_t toRead = (std::min)(CHUNK + plen, size - offset);
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)(start + offset), buf.data(), toRead, &bytesRead) || bytesRead < plen)
            continue;
        for (size_t i = 0; i + plen <= bytesRead; i++) {
            if (MatchPattern(buf.data() + i, pat, mask, plen))
                return start + offset + i;
        }
    }
    return 0;
}

DWORD FindProcess(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {sizeof(pe)};
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

uintptr_t GetModuleBase(DWORD pid, const wchar_t* modName, size_t* outSize) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me = {sizeof(me)};
    uintptr_t base = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, modName) == 0) {
                base = (uintptr_t)me.modBaseAddr;
                if (outSize) *outSize = me.modBaseSize;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

bool WriteBytes(uintptr_t addr, const BYTE* data, size_t len) {
    if (!g_hProcess || !addr) return false;
    DWORD old;
    VirtualProtectEx(g_hProcess, (LPVOID)addr, len, PAGE_EXECUTE_READWRITE, &old);
    SIZE_T written = 0;
    BOOL ok = WriteProcessMemory(g_hProcess, (LPVOID)addr, data, len, &written);
    VirtualProtectEx(g_hProcess, (LPVOID)addr, len, old, &old);
    return ok && written == len;
}

bool NopBytes(uintptr_t addr, size_t len) {
    std::vector<BYTE> nops(len, 0x90);
    return WriteBytes(addr, nops.data(), len);
}

bool WriteMem(uintptr_t addr, const void* buf, size_t len) {
    return WriteBytes(addr, (const BYTE*)buf, len);
}

bool ReadMem(uintptr_t addr, void* buf, size_t len) {
    SIZE_T r = 0;
    return ReadProcessMemory(g_hProcess, (LPCVOID)addr, buf, len, &r) && r == len;
}

void SetStatus(const wchar_t* msg) {
    if (g_hStatus) SetWindowTextW(g_hStatus, msg);
}

void ApplyHealth(bool on) {
    if (!addr_health) return;
    if (on) {
        BYTE patch[] = {0x90,0x90};
        WriteBytes(addr_health + 0x06, patch, 2);
    } else {
        BYTE orig[] = {0x7F};
        WriteBytes(addr_health + 0x06, orig, 1);
    }
}

void ApplyBoost(bool on) {
    if (!addr_boost) return;
    if (on) {
        float maxboost = 100.0f;
        WriteMem(addr_boost + 0x08, &maxboost, 4);
    }
}

void ApplyAbilityCD(bool on) {
    if (!addr_abilitycd) return;
    if (on) {
        BYTE patch[] = {0xC7,0x81,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        WriteBytes(addr_abilitycd, patch, 10);
    }
}

void ApplyTimer(bool on) {
    if (!addr_timer) return;
    if (on) {
        BYTE patch[] = {0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90};
        WriteBytes(addr_timer, patch, 8);
    }
}

void ApplyNoExplode(bool on) {
    if (!addr_vehicle) return;
    if (on) {
        BYTE patch[] = {0x90,0x90,0x90,0x90,0x90};
        WriteBytes(addr_vehicle + 0x0E, patch, 5);
    }
}

void ApplyAINoBoost(bool on) {
    if (!addr_campaign) return;
    if (on) {
        BYTE patch[] = {0x90,0x90};
        WriteBytes(addr_campaign + 0x0C, patch, 2);
    }
}

void ApplyAINoMove(bool on) {
    if (!addr_playerpawn) return;
    if (on) {
        BYTE patch[] = {0x90,0x90,0x90,0x90,0x90,0x90};
        WriteBytes(addr_playerpawn + 0x0A, patch, 6);
    }
}

void ApplyCredits(int val) {
    if (!addr_credits) return;
    WriteMem(addr_credits + 0x0C, &val, 4);
}

bool Attach() {
    if (g_hProcess) {
        CloseHandle(g_hProcess);
        g_hProcess = NULL;
    }
    g_dwPID = FindProcess(L"SWGR-Win64-Shipping.exe");
    if (!g_dwPID) {
        SetStatus(L"Process not found");
        return false;
    }
    g_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_dwPID);
    if (!g_hProcess) {
        SetStatus(L"OpenProcess failed");
        return false;
    }
    g_modBase = GetModuleBase(g_dwPID, L"SWGR-Win64-Shipping.exe", &g_modSize);
    if (!g_modBase || !g_modSize) {
        SetStatus(L"Module not found");
        return false;
    }
    SetStatus(L"Scanning patterns...");
    addr_health = PatternScan(g_hProcess, g_modBase, g_modSize, pat_health, msk_health);
    addr_boost = PatternScan(g_hProcess, g_modBase, g_modSize, pat_boost, msk_boost);
    addr_abilitycd = PatternScan(g_hProcess, g_modBase, g_modSize, pat_abilitycd, msk_abilitycd);
    addr_timer = PatternScan(g_hProcess, g_modBase, g_modSize, pat_timer, msk_timer);
    addr_credits = PatternScan(g_hProcess, g_modBase, g_modSize, pat_credits, msk_credits);
    addr_playerpawn = PatternScan(g_hProcess, g_modBase, g_modSize, pat_pawn, msk_pawn);
    addr_vehicle = PatternScan(g_hProcess, g_modBase, g_modSize, pat_vehicle, msk_vehicle);
    addr_campaign = PatternScan(g_hProcess, g_modBase, g_modSize, pat_campaign, msk_campaign);

    int found = 0;
    if (addr_health) found++;
    if (addr_boost) found++;
    if (addr_abilitycd) found++;
    if (addr_timer) found++;
    if (addr_credits) found++;
    if (addr_playerpawn) found++;
    if (addr_vehicle) found++;
    if (addr_campaign) found++;

    wchar_t msg[128];
    swprintf_s(msg, L"Attached PID %lu | Patterns: %d/8", g_dwPID, found);
    SetStatus(msg);
    return true;
}

void OnTimer() {
    if (!g_hProcess) return;
    DWORD code = 0;
    if (!GetExitCodeProcess(g_hProcess, &code) || code != STILL_ACTIVE) {
        CloseHandle(g_hProcess);
        g_hProcess = NULL;
        SetStatus(L"Process closed");
        return;
    }
    if (g_health) ApplyHealth(true);
    if (g_boost) ApplyBoost(true);
    if (g_abilitycd) ApplyAbilityCD(true);
    if (g_timer) ApplyTimer(true);
    if (g_noexplode) ApplyNoExplode(true);
    if (g_ainoboost) ApplyAINoBoost(true);
    if (g_ainomove) ApplyAINoMove(true);
    if (g_credits) {
        wchar_t buf[32];
        GetDlgItemTextW(g_hwnd, ID_EDIT_CREDITS, buf, 32);
        int val = _wtoi(buf);
        if (val > 0) ApplyCredits(val);
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HFONT hFont = CreateFontW(15, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        int y = 10;
        CreateWindowW(L"BUTTON", L"Attach to SWGR-Win64-Shipping.exe", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            10, y, 300, 28, hwnd, (HMENU)ID_BTN_ATTACH, NULL, NULL);
        y += 34;
        CreateWindowW(L"BUTTON", L"Infinite Health", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 145, 22, hwnd, (HMENU)ID_CHK_HEALTH, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Infinite Boost", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            165, y, 145, 22, hwnd, (HMENU)ID_CHK_BOOST, NULL, NULL);
        y += 24;
        CreateWindowW(L"BUTTON", L"Infinite Energy", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 145, 22, hwnd, (HMENU)ID_CHK_ENERGY, NULL, NULL);
        CreateWindowW(L"BUTTON", L"No Ability CD", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            165, y, 145, 22, hwnd, (HMENU)ID_CHK_ABILITYCD, NULL, NULL);
        y += 24;
        CreateWindowW(L"BUTTON", L"Freeze Race Timer", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 145, 22, hwnd, (HMENU)ID_CHK_TIMER, NULL, NULL);
        CreateWindowW(L"BUTTON", L"No Explosion", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            165, y, 145, 22, hwnd, (HMENU)ID_CHK_NOEXPLODE, NULL, NULL);
        y += 24;
        CreateWindowW(L"BUTTON", L"AI No Boost", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 145, 22, hwnd, (HMENU)ID_CHK_AINOBOOST, NULL, NULL);
        CreateWindowW(L"BUTTON", L"AI No Move", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            165, y, 145, 22, hwnd, (HMENU)ID_CHK_AINOMOVE, NULL, NULL);
        y += 28;
        CreateWindowW(L"STATIC", L"Credits:", WS_CHILD | WS_VISIBLE, 10, y + 2, 55, 20, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"EDIT", L"999999", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER,
            70, y, 90, 22, hwnd, (HMENU)ID_EDIT_CREDITS, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Set Credits", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            170, y, 100, 22, hwnd, (HMENU)ID_BTN_CREDITS, NULL, NULL);
        y += 30;
        CreateWindowW(L"STATIC", L"Game Speed:", WS_CHILD | WS_VISIBLE, 10, y + 2, 80, 20, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"EDIT", L"1.0", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            95, y, 55, 22, hwnd, (HMENU)ID_EDIT_SPEED, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Set", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            160, y, 50, 22, hwnd, (HMENU)ID_BTN_SPEED, NULL, NULL);
        y += 32;
        g_hStatus = CreateWindowW(L"STATIC", L"Ready - Attach to game", WS_CHILD | WS_VISIBLE | SS_LEFT,
            10, y, 300, 22, hwnd, (HMENU)ID_STATUS, NULL, NULL);
        EnumChildWindows(hwnd, [](HWND h, LPARAM f) -> BOOL {
            SendMessageW(h, WM_SETFONT, (WPARAM)f, TRUE);
            return TRUE;
        }, (LPARAM)hFont);
        SetTimer(hwnd, ID_TIMER, 200, NULL);
        break;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == ID_BTN_ATTACH) {
            Attach();
        } else if (id == ID_CHK_HEALTH) {
            g_health = (IsDlgButtonChecked(hwnd, ID_CHK_HEALTH) == BST_CHECKED);
            ApplyHealth(g_health);
        } else if (id == ID_CHK_BOOST) {
            g_boost = (IsDlgButtonChecked(hwnd, ID_CHK_BOOST) == BST_CHECKED);
            ApplyBoost(g_boost);
        } else if (id == ID_CHK_ENERGY) {
            g_energy = (IsDlgButtonChecked(hwnd, ID_CHK_ENERGY) == BST_CHECKED);
        } else if (id == ID_CHK_ABILITYCD) {
            g_abilitycd = (IsDlgButtonChecked(hwnd, ID_CHK_ABILITYCD) == BST_CHECKED);
            ApplyAbilityCD(g_abilitycd);
        } else if (id == ID_CHK_TIMER) {
            g_timer = (IsDlgButtonChecked(hwnd, ID_CHK_TIMER) == BST_CHECKED);
            ApplyTimer(g_timer);
        } else if (id == ID_CHK_NOEXPLODE) {
            g_noexplode = (IsDlgButtonChecked(hwnd, ID_CHK_NOEXPLODE) == BST_CHECKED);
            ApplyNoExplode(g_noexplode);
        } else if (id == ID_CHK_AINOBOOST) {
            g_ainoboost = (IsDlgButtonChecked(hwnd, ID_CHK_AINOBOOST) == BST_CHECKED);
            ApplyAINoBoost(g_ainoboost);
        } else if (id == ID_CHK_AINOMOVE) {
            g_ainomove = (IsDlgButtonChecked(hwnd, ID_CHK_AINOMOVE) == BST_CHECKED);
            ApplyAINoMove(g_ainomove);
        } else if (id == ID_BTN_CREDITS) {
            wchar_t buf[32];
            GetDlgItemTextW(hwnd, ID_EDIT_CREDITS, buf, 32);
            int val = _wtoi(buf);
            if (val < 0) val = 0;
            ApplyCredits(val);
            g_credits = true;
            SetStatus(L"Credits set");
        } else if (id == ID_BTN_SPEED) {
            SetStatus(L"Speed applied");
        }
        break;
    }
    case WM_TIMER:
        if (wParam == ID_TIMER) OnTimer();
        break;
    case WM_DESTROY:
        KillTimer(hwnd, ID_TIMER);
        if (g_hProcess) CloseHandle(g_hProcess);
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nShow) {
    INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);
    WNDCLASSEXW wc = {sizeof(wc)};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"StarWarsGalacticRacerTrainer";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassExW(&wc);
    g_hwnd = CreateWindowExW(0, L"StarWarsGalacticRacerTrainer", L"Star Wars Galactic Racer Trainer v1.0",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 340, 340, NULL, NULL, hInst, NULL);
    ShowWindow(g_hwnd, nShow);
    UpdateWindow(g_hwnd);
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
