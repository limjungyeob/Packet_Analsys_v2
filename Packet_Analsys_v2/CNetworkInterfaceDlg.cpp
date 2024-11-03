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
}


BEGIN_MESSAGE_MAP(CNetworkInterfaceDlg, CDialog)
END_MESSAGE_MAP()


// CNetworkInterfaceDlg 메시지 처리기
