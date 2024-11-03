#pragma once
#include "afxdialogex.h"


// CNetworkInterfaceDlg 대화 상자

class CNetworkInterfaceDlg : public CDialog
{
	DECLARE_DYNAMIC(CNetworkInterfaceDlg)

public:
	CNetworkInterfaceDlg(CWnd* pParent = nullptr);   // 표준 생성자입니다.
	virtual ~CNetworkInterfaceDlg();

// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CNetworkInterfaceDlg };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

	DECLARE_MESSAGE_MAP()
};
