#include <vector>
// Packet_Analsys_v2Dlg.h: 헤더 파일
//

#pragma once


// CPacketAnalsysv2Dlg 대화 상자
class CPacketAnalsysv2Dlg : public CDialogEx
{
// 생성입니다.
public:
	CPacketAnalsysv2Dlg(CWnd* pParent = nullptr);	// 표준 생성자입니다.

// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PACKET_ANALSYS_V2_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 지원입니다.


// 구현입니다.
protected:
	HICON m_hIcon;

	// 생성된 메시지 맵 함수
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnTimer(UINT_PTR nIDEvent); // OnTimer 함수 선언
	afx_msg void DisplayHexDump(const u_char* pkt_data, int len); // OnTimer 함수 선언
	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_listCtrl;
	afx_msg void OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnBnClickedCaptureButton();
	afx_msg void OnBnClickedStopButton();
	afx_msg void OnEnChangePacketDetails();
	void AddPacketToList(int packetNum, const struct pcap_pkthdr* header, const u_char* pkt_data);
	CEdit m_editPacketDetails;

private:
	CWinThread* m_pCaptureThread; // 캡처 쓰레드 포인터
	bool m_bCapturing; // 캡처 중인지 여부를 나타내는 플래그
	bool m_bAutoScroll; // 자동 스크롤 여부
	static UINT CaptureThreadFunc(LPVOID pParam); // 쓰레드 함수
	std::vector<std::vector<u_char>> m_packetStorage;
public:
	CEdit m_editPacketHexDump;
};
