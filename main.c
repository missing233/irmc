#define _CRT_SECURE_NO_WARNINGS
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

/*
 * REDACTED
 * The real values are not included here.
 * Placeholder bytes below are for test only.
 * Any keys generated using these values are INVALID.
 */

const uint8_t HMAC_KEY[16] = {
    0x01, 0x01, 0x04, 0x05, 0x01, 0x04, 0x01, 0x09, 0x01, 0x09, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00};

const uint8_t HMAC_MSG[16] = {
    0x01, 0x01, 0x04, 0x05, 0x01, 0x04, 0x01, 0x09, 0x01, 0x09, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00};

const uint8_t AES_IV[16] = {
    0x01, 0x01, 0x04, 0x05, 0x01, 0x04, 0x01, 0x09, 0x01, 0x09, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00};

typedef struct
{
    BLOBHEADER hdr;
    DWORD len;
    BYTE key[16];
} KEY_BLOB_128;

uint32_t spd_crc32(const char *serial)
{
    uint32_t table[256], x = 1;
    for (int i = 0; i < 256; i++)
    {
        uint32_t entry = (uint32_t)i << 24;
        for (int k = 0; k < 8; k++)
            entry = (entry & 0x80000000) ? ((entry << 1) ^ 0x4c11db7) : (entry << 1);
        table[i] = entry;
    }
    size_t len = strlen(serial);
    for (size_t i = 0; i < len; i++)
        x = (table[((x >> 24) ^ (uint8_t)serial[i]) & 0xff] ^ (x << 8));
    return x;
}

void base32_encode(const uint8_t *data, int length, char *result)
{
    const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    int val = 0, valb = 0;
    char *out = result;
    for (int i = 0; i < length; i++)
    {
        val = (val << 8) | data[i];
        valb += 8;
        while (valb >= 5)
        {
            *out++ = base32_chars[(val >> (valb - 5)) & 0x1F];
            valb -= 5;
        }
    }
    if (valb > 0)
        *out++ = base32_chars[(val << (5 - valb)) & 0x1F];
    *out = 0;
}

void calculate_key(const char *serial, int features_code, int is_rx, char *output_buf)
{
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hHmacKey = 0, hAesKey = 0;
    HCRYPTHASH hHmacHash = 0;
    uint8_t data[32] = {0};
    memcpy(data, "iRMC", 4);
    data[4] = features_code & 0xFF;
    uint32_t struct_data = is_rx ? 0xffffff05 : 0xffffff00;
    data[8] = (struct_data >> 24) & 0xFF;
    data[9] = (struct_data >> 16) & 0xFF;
    data[10] = (struct_data >> 8) & 0xFF;
    data[11] = (struct_data) & 0xFF;
    uint32_t crc = spd_crc32(serial);
    data[12] = crc & 0xFF;
    data[13] = (crc >> 8) & 0xFF;
    data[14] = (crc >> 16) & 0xFF;
    data[15] = (crc >> 24) & 0xFF;

    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        sprintf(output_buf, "Err: Init");
        return;
    }
    KEY_BLOB_128 kbHmac = {{PLAINTEXTKEYBLOB, CUR_BLOB_VERSION, 0, CALG_RC2}, 16, {0}};
    memcpy(kbHmac.key, HMAC_KEY, 16);
    if (CryptImportKey(hProv, (BYTE *)&kbHmac, sizeof(kbHmac), 0, CRYPT_IPSEC_HMAC_KEY, &hHmacKey))
    {
        if (CryptCreateHash(hProv, CALG_HMAC, hHmacKey, 0, &hHmacHash))
        {
            HMAC_INFO HmacInfo = {0};
            HmacInfo.HashAlgid = CALG_SHA1;
            CryptSetHashParam(hHmacHash, HP_HMAC_INFO, (BYTE *)&HmacInfo, 0);
            for (int i = 0; i < 4; i++)
                CryptHashData(hHmacHash, HMAC_MSG, 16, 0);
            BYTE derived_key[20];
            DWORD dk_len = 20;
            CryptGetHashParam(hHmacHash, HP_HASHVAL, derived_key, &dk_len, 0);
            KEY_BLOB_128 kbAes = {{PLAINTEXTKEYBLOB, CUR_BLOB_VERSION, 0, CALG_AES_128}, 16, {0}};
            memcpy(kbAes.key, derived_key, 16);
            if (CryptImportKey(hProv, (BYTE *)&kbAes, sizeof(kbAes), 0, 0, &hAesKey))
            {
                DWORD mode = CRYPT_MODE_CBC, dlen = 16, blen = 32;
                CryptSetKeyParam(hAesKey, KP_MODE, (BYTE *)&mode, 0);
                CryptSetKeyParam(hAesKey, KP_IV, (BYTE *)AES_IV, 0);
                if (CryptEncrypt(hAesKey, 0, TRUE, 0, data, &dlen, blen))
                {
                    char b32_str[40];
                    base32_encode(data, 16, b32_str);
                    output_buf[0] = 0;
                    for (int i = 0; i < strlen(b32_str); i++)
                    {
                        if (i > 0 && i % 4 == 0)
                            strcat(output_buf, "-");
                        char tmp[2] = {b32_str[i], 0};
                        strcat(output_buf, tmp);
                    }
                }
                else
                    sprintf(output_buf, "Err: Encrypt");
                CryptDestroyKey(hAesKey);
            }
            else
                sprintf(output_buf, "Err: AES Key");
            CryptDestroyHash(hHmacHash);
        }
        CryptDestroyKey(hHmacKey);
    }
    if (hProv)
        CryptReleaseContext(hProv, 0);
}

#define ID_BTN_GENERATE 101
#define ID_EDIT_SERIAL 102
#define ID_EDIT_RESULT 103
#define ID_RADIO_TX 104
#define ID_RADIO_RX 105
#define ID_CHK_KVM 106
#define ID_CHK_MEDIA 107
#define ID_CHK_ELCM 108
#define ID_STATIC_WARN 109

HWND hEditSerial, hEditResult, hRadioTX, hRadioRX, hBtnGen;
HWND hChkKVM, hChkMedia, hChkELCM, hStaticWarn;

void UpdateUIState()
{
    int is_tx = (SendMessage(hRadioTX, BM_GETCHECK, 0, 0) == BST_CHECKED);
    int is_elcm = (SendMessage(hChkELCM, BM_GETCHECK, 0, 0) == BST_CHECKED);
    int is_kvm = (SendMessage(hChkKVM, BM_GETCHECK, 0, 0) == BST_CHECKED);
    int is_media = (SendMessage(hChkMedia, BM_GETCHECK, 0, 0) == BST_CHECKED);

    if (is_tx && is_elcm)
    {
        ShowWindow(hStaticWarn, SW_SHOW);
    }
    else
    {
        ShowWindow(hStaticWarn, SW_HIDE);
    }

    if (!is_kvm && !is_media && !is_elcm)
    {
        EnableWindow(hBtnGen, FALSE);
    }
    else
    {
        EnableWindow(hBtnGen, TRUE);
    }
}

static HFONT g_hFont = NULL;
static HFONT g_hFontBold = NULL;

static BOOL CALLBACK SetFontEnumProc(HWND child, LPARAM lParam)
{
    HFONT hFont = (HFONT)lParam;
    SendMessage(child, WM_SETFONT, (WPARAM)hFont, TRUE);
    return TRUE;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_CREATE:
        CreateWindow("STATIC", "Serial No.", WS_VISIBLE | WS_CHILD, 20, 20, 100, 20, hwnd, NULL, NULL, NULL);
        hEditSerial = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 130, 20, 180, 20, hwnd, (HMENU)ID_EDIT_SERIAL, NULL, NULL);

        CreateWindow("STATIC", "Chassis Type", WS_VISIBLE | WS_CHILD, 20, 60, 100, 20, hwnd, NULL, NULL, NULL);
        hRadioTX = CreateWindow("BUTTON", "TX", WS_VISIBLE | WS_CHILD | WS_GROUP | WS_TABSTOP | BS_AUTORADIOBUTTON, 130, 60, 90, 20, hwnd, (HMENU)ID_RADIO_TX, NULL, NULL);
        hRadioRX = CreateWindow("BUTTON", "RX", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON, 230, 60, 80, 20, hwnd, (HMENU)ID_RADIO_RX, NULL, NULL);
        SendMessage(hRadioTX, BM_SETCHECK, BST_CHECKED, 0);

        CreateWindow("STATIC", "Features", WS_VISIBLE | WS_CHILD, 20, 100, 100, 20, hwnd, NULL, NULL, NULL);
        hChkKVM = CreateWindow("BUTTON", "KVM", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 130, 100, 200, 20, hwnd, (HMENU)ID_CHK_KVM, NULL, NULL);
        hChkMedia = CreateWindow("BUTTON", "Virtual Media", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 130, 125, 200, 20, hwnd, (HMENU)ID_CHK_MEDIA, NULL, NULL);
        hChkELCM = CreateWindow("BUTTON", "eLCM", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 130, 150, 200, 20, hwnd, (HMENU)ID_CHK_ELCM, NULL, NULL);
        // SendMessage(hChkKVM, BM_SETCHECK, BST_CHECKED, 0);
        // SendMessage(hChkMedia, BM_SETCHECK, BST_CHECKED, 0);
        // SendMessage(hChkELCM, BM_SETCHECK, BST_CHECKED, 0);

        hStaticWarn = CreateWindow("STATIC", "Key may not be valid for TX chassis with eLCM enabled",
                                   WS_CHILD, 20, 180, 420, 20, hwnd, (HMENU)ID_STATIC_WARN, NULL, NULL);

        hBtnGen = CreateWindow("BUTTON", "Generate", WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON, 50, 210, 200, 30, hwnd, (HMENU)ID_BTN_GENERATE, NULL, NULL);

        CreateWindow("STATIC", "Key", WS_VISIBLE | WS_CHILD, 20, 250, 100, 20, hwnd, NULL, NULL, NULL);
        hEditResult = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_READONLY | ES_AUTOHSCROLL, 20, 275, 350, 20, hwnd, (HMENU)ID_EDIT_RESULT, NULL, NULL);

        g_hFont = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             DEFAULT_QUALITY, DEFAULT_PITCH, "MS Shell Dlg 2");
        EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)g_hFont);

        g_hFontBold = CreateFont(15, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                 DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                 DEFAULT_QUALITY, DEFAULT_PITCH, "MS Shell Dlg 2");
        SendMessage(hStaticWarn, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);

        UpdateUIState();
        break;

    case WM_CTLCOLORSTATIC:
        if ((HWND)lParam == hStaticWarn)
        {
            SetTextColor((HDC)wParam, RGB(255, 0, 0));
            SetBkMode((HDC)wParam, TRANSPARENT);
            return (LRESULT)GetStockObject(NULL_BRUSH);
        }
        return (LRESULT)GetStockObject(WHITE_BRUSH);

    case WM_COMMAND:
        if (HIWORD(wParam) == BN_CLICKED)
        {
            if (LOWORD(wParam) == ID_CHK_ELCM)
            {
                if (SendMessage(hChkELCM, BM_GETCHECK, 0, 0) == BST_CHECKED)
                {
                    SendMessage(hChkKVM, BM_SETCHECK, BST_CHECKED, 0);
                    SendMessage(hChkMedia, BM_SETCHECK, BST_CHECKED, 0);
                }
            }
            if (LOWORD(wParam) == ID_CHK_MEDIA)
            {
                if (SendMessage(hChkMedia, BM_GETCHECK, 0, 0) == BST_CHECKED)
                {
                    SendMessage(hChkKVM, BM_SETCHECK, BST_CHECKED, 0);
                }
                else
                {
                    SendMessage(hChkELCM, BM_SETCHECK, BST_UNCHECKED, 0);
                }
            }
            if (LOWORD(wParam) == ID_CHK_KVM)
            {
                if (SendMessage(hChkKVM, BM_GETCHECK, 0, 0) == BST_UNCHECKED)
                {
                    SendMessage(hChkMedia, BM_SETCHECK, BST_UNCHECKED, 0);
                    SendMessage(hChkELCM, BM_SETCHECK, BST_UNCHECKED, 0);
                }
            }
            UpdateUIState();
        }

        if (LOWORD(wParam) == ID_BTN_GENERATE)
        {
            char serial[128], output[128];
            GetWindowText(hEditSerial, serial, 128);

            char clean_serial[128];
            int j = 0;
            for (int i = 0; serial[i]; i++)
                if (!isspace((unsigned char)serial[i]))
                    clean_serial[j++] = serial[i];
            clean_serial[j] = 0;

            if (strlen(clean_serial) == 0)
            {
                MessageBox(hwnd, "Empty SN", "Error", MB_ICONERROR);
                break;
            }

            int feat_code = 0;
            if (SendMessage(hChkELCM, BM_GETCHECK, 0, 0) == BST_CHECKED)
                feat_code = 0x0F;
            else if (SendMessage(hChkMedia, BM_GETCHECK, 0, 0) == BST_CHECKED)
                feat_code = 0x03;
            else if (SendMessage(hChkKVM, BM_GETCHECK, 0, 0) == BST_CHECKED)
                feat_code = 0x01;

            if (feat_code == 0)
            {
                MessageBox(hwnd, "No feature selected", "Error", MB_ICONERROR);
                break;
            }

            int is_rx = (SendMessage(hRadioRX, BM_GETCHECK, 0, 0) == BST_CHECKED);
            calculate_key(clean_serial, feat_code, is_rx, output);
            SetWindowText(hEditResult, output);
        }
        break;

    case WM_DESTROY:
        if (g_hFont) { DeleteObject(g_hFont); g_hFont = NULL; }
        if (g_hFontBold) { DeleteObject(g_hFontBold); g_hFontBold = NULL; }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    const char CLASS_NAME[] = "Keygen";
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0, CLASS_NAME, "iRMC S4/S5 Keygen",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 360,
        NULL, NULL, hInstance, NULL);

    if (hwnd == NULL)
        return 0;
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}