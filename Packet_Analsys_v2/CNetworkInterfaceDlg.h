#pragma once
#include "afxdialogex.h"
#include <pcap.h>

// CNetworkInterfaceDlg 대화 상자

class CNetworkInterfaceDlg : public CDialog
{
	DECLARE_DYNAMIC(CNetworkInterfaceDlg)

public:
	CNetworkInterfaceDlg(CWnd* pParent = nullptr);   // 표준 생성자입니다.
	virtual ~CNetworkInterfaceDlg();
	CString GetSelectedInterface() const; // 선택된 네트워크 인터페이스를 반환하는 함수
	CListCtrl mlistCTRLInterfaces;
	virtual BOOL OnInitDialog(); // 다이얼로그 초기화 함수
	afx_msg void OnBnClickedOk(); // "확인" 버튼 클릭 시 호출될 함수

// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CNetworkInterfaceDlg };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

	DECLARE_MESSAGE_MAP()

private:
	CString m_selectedInterface; // 사용자가 선택한 네트워크 인터페이스 정보를 저장하는 변수
};
