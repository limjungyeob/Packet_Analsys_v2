// CNetworkInterfaceDlg.cpp: 구현 파일
//

#include "pch.h"
#include "Packet_Analsys_v2.h"
#include "afxdialogex.h"
#include "CNetworkInterfaceDlg.h"


// CNetworkInterfaceDlg 대화 상자

IMPLEMENT_DYNAMIC(CNetworkInterfaceDlg, CDialog)

CNetworkInterfaceDlg::CNetworkInterfaceDlg(CWnd* pParent /*=nullptr*/)
	: CDialog(IDD_CNetworkInterfaceDlg, pParent)
{

}

CNetworkInterfaceDlg::~CNetworkInterfaceDlg()
{
}

void CNetworkInterfaceDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_INTERFACES, mlistCTRLInterfaces);
}


BEGIN_MESSAGE_MAP(CNetworkInterfaceDlg, CDialog)
    ON_BN_CLICKED(IDOK, &CNetworkInterfaceDlg::OnBnClickedOk)
END_MESSAGE_MAP()

BOOL CNetworkInterfaceDlg::OnInitDialog()
{
    CDialog::OnInitDialog();

    mlistCTRLInterfaces.InsertColumn(0, _T("Interface Name"), LVCFMT_LEFT, 300);
    mlistCTRLInterfaces.InsertColumn(1, _T("Interface Description"), LVCFMT_LEFT, 300);
    mlistCTRLInterfaces.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    // pcap을 사용하여 네트워크 인터페이스 목록을 가져옴
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        AfxMessageBox(_T("Error finding devices"));
        return TRUE;
    }

    int index = 0;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        CString interfaceName(d->name);
        CString interfaceDescription(d->description ? d->description : "No description available");
        int itemIndex = mlistCTRLInterfaces.InsertItem(index, interfaceName);
        mlistCTRLInterfaces.SetItemText(itemIndex, 1, interfaceDescription);
        index++;
    }

    // pcap 자원 해제
    pcap_freealldevs(alldevs);

    return TRUE;
}


void CNetworkInterfaceDlg::OnBnClickedOk()
{
    // 사용자가 선택한 인터페이스를 저장
    int selectedIndex = mlistCTRLInterfaces.GetNextItem(-1, LVNI_SELECTED);
    if (selectedIndex != -1) {
        m_selectedInterface = mlistCTRLInterfaces.GetItemText(selectedIndex, 0);
        TRACE(_T("Selected Interface: %s\n"), m_selectedInterface);
    }
    else {
        AfxMessageBox(_T("Please select a network interface."));
        return;
    }

    CDialog::OnOK();
}

CString CNetworkInterfaceDlg::GetSelectedInterface() const
{
    TRACE(_T("GetSelectedInterface# : %s\n"), m_selectedInterface);
    return m_selectedInterface; // 사용자가 선택한 네트워크 인터페이스 반환
}
// CNetworkInterfaceDlg 메시지 처리기
