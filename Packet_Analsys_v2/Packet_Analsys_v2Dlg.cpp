
// Packet_Analsys_v2Dlg.cpp: 구현 파일
//기본 헤더파일
#include "pch.h"
#include "framework.h"
#include "Packet_Analsys_v2.h"
#include "Packet_Analsys_v2Dlg.h"
#include "afxdialogex.h"
#include <pcap.h>	//패킷 캡처 라이브러리
#include <winsock2.h>	//네트워크 관련함수
#include <Ws2tcpip.h>	//IP 주소 관련 함수
#pragma comment(lib, "Ws2_32.lib")	//Ws2_32 라이브러리 링크
#include "CNetworkInterfaceDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// 구조체 선언
struct ethernet_header {
	u_char dest_mac[6];	//목적지 MAC 주소
	u_char src_mac[6];	//소스 MAC 주소
	u_short type;	// 이더넷 타입(ex IP,ARP)
};

// IP 헤더 구조체 정의
struct ip_header {
	unsigned char ip_header_len : 4; // 헤더 길이
	unsigned char ip_version : 4;    // IP 버전
	unsigned char ip_tos;            // 서비스 타입
	unsigned short ip_total_length;  // 총 길이
	unsigned short ip_id;            // 식별자
	unsigned short ip_flags : 3;     // 플래그
	unsigned short ip_offset : 13;   // 프래그먼트 오프셋
	unsigned char ip_ttl;            // 생존 시간 (TTL)
	unsigned char ip_protocol;       // 프로토콜
	unsigned short ip_checksum;      // 체크섬
	struct in_addr ip_srcaddr;       // 소스 IP 주소
	struct in_addr ip_destaddr;      // 목적지 IP 주소
};

struct tcp_header {
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;
	unsigned char data_offset : 4;
	unsigned char reserved : 4;
	unsigned char flags;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
};

// 응용 프로그램 정보에 사용되는 CAboutDlg 대화 상자입니다.

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

// 구현입니다.
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CPacketAnalsysv2Dlg 대화 상자



CPacketAnalsysv2Dlg::CPacketAnalsysv2Dlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_PACKET_ANALSYS_V2_DIALOG, pParent), m_bCapturing(false), m_pCaptureThread(nullptr),m_bAutoScroll(nullptr)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);	//아이콘 설정
}

//데이터 교환 함수 정의
void CPacketAnalsysv2Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_listCtrl);	//리스트 컨트롤과 연결
	DDX_Control(pDX, IDC_PACKET_DETAILS, m_editPacketDetails);	//에디트 컨트롤과 연결
	DDX_Control(pDX, IDC_PACKET_HEXDUMP, m_editPacketHexDump);
}

//메시지 맵 정의
BEGIN_MESSAGE_MAP(CPacketAnalsysv2Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CPacketAnalsysv2Dlg::OnLvnItemchangedList1)
	ON_BN_CLICKED(IDC_CAPTURE_BUTTON, &CPacketAnalsysv2Dlg::OnBnClickedCaptureButton)
	ON_BN_CLICKED(IDC_STOP_BUTTON, &CPacketAnalsysv2Dlg::OnBnClickedStopButton)
	ON_EN_CHANGE(IDC_PACKET_DETAILS, &CPacketAnalsysv2Dlg::OnEnChangePacketDetails)
	ON_BN_CLICKED(IDC_CONNECT_BUTTON, &CPacketAnalsysv2Dlg::OnBnClickedConnectButton)
END_MESSAGE_MAP()


// CPacketAnalsysv2Dlg 메시지 처리기

BOOL CPacketAnalsysv2Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 시스템 메뉴에 "정보..." 메뉴 항목을 추가합니다.

	// IDM_ABOUTBOX는 시스템 명령 범위에 있어야 합니다.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 이 대화 상자의 아이콘을 설정합니다.  응용 프로그램의 주 창이 대화 상자가 아닐 경우에는
	//  프레임워크가 이 작업을 자동으로 수행합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, FALSE);		// 작은 아이콘을 설정합니다.

	// TODO: 여기에 추가 초기화 작업을 추가합니다.
	// CListCtrl 초기화 - 열(Column) 추가
	m_listCtrl.InsertColumn(0, _T("No."), LVCFMT_LEFT, 50);
	m_listCtrl.InsertColumn(1, _T("Time"), LVCFMT_LEFT, 150);
	m_listCtrl.InsertColumn(2, _T("Source IP"), LVCFMT_LEFT, 150);
	m_listCtrl.InsertColumn(3, _T("Destination IP"), LVCFMT_LEFT, 150);
	m_listCtrl.InsertColumn(4, _T("Protocol"), LVCFMT_LEFT, 100);
	m_listCtrl.InsertColumn(5, _T("Length"), LVCFMT_LEFT, 100);
	m_listCtrl.InsertColumn(6, _T("Info"), LVCFMT_LEFT, 300);
	// 선택 모드 설정 (옵션)
	m_listCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);	//리스트 스타일
	m_bAutoScroll = true; // 자동 스크롤 활성화
	UpdateCaptureButtonState();
	return TRUE;  // 포커스를 컨트롤에 설정하지 않으면 TRUE를 반환합니다.
}

// 시스템 명령 처리기
void CPacketAnalsysv2Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 대화 상자에 최소화 단추를 추가할 경우 아이콘을 그리려면
//  아래 코드가 필요합니다.  문서/뷰 모델을 사용하는 MFC 애플리케이션의 경우에는
//  프레임워크에서 이 작업을 자동으로 수행합니다.

void CPacketAnalsysv2Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 그리기를 위한 디바이스 컨텍스트입니다.

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 클라이언트 사각형에서 아이콘을 가운데에 맞춥니다.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 아이콘을 그립니다.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// 사용자가 최소화된 창을 끄는 동안에 커서가 표시되도록 시스템에서
//  이 함수를 호출합니다.
HCURSOR CPacketAnalsysv2Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CPacketAnalsysv2Dlg::OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	//선택항목의 인덱스를 가져온다.
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	int nIndex = pNMLV->iItem;

	if (nIndex >= 0 && nIndex < m_packetStorage.size()) {
		const u_char* pkt_data = m_packetStorage[nIndex].data();	//벡터에서 꺼내오기.
		int pkt_length = m_packetStorage[nIndex].size(); // 패킷 길이 가져오기
		// 이더넷, IP, TCP 헤더 파싱 및 Edit 컨트롤에 출력
		const ethernet_header* ethHeader = reinterpret_cast<const ethernet_header*>(pkt_data);	//이더넷 헤더는 패킷 맨 앞에 위치.
		const ip_header* ipHeader = reinterpret_cast<const ip_header*>(pkt_data + 14);	//IP 헤더는 이더넷 헤더의 길이 14바이트 앞에 위치.
		const tcp_header* tcpHeader = reinterpret_cast<const tcp_header*>(pkt_data + 14 + (ipHeader->ip_header_len * 4));	//이더넷 헤더 + IP 헤더의 끝 앞에 위치.
		//이더넷 헤더와 IP 헤더, TCP헤더는 고정된 바이너리 포맷을 가지고있어 구조체 필드 순서와 일치하면 해당 위치의 데이터를 해석할수있음.
		// Ethernet 헤더 파싱 및 출력
		CString ethernetDetails;
		ethernetDetails.Format(_T("Ethernet Header:\r\n")
			_T(" - Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\r\n")
			_T(" - Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\r\n")
			_T(" - Type: %04X\r\n"),
			ethHeader->src_mac[0], ethHeader->src_mac[1], ethHeader->src_mac[2],
			ethHeader->src_mac[3], ethHeader->src_mac[4], ethHeader->src_mac[5],
			ethHeader->dest_mac[0], ethHeader->dest_mac[1], ethHeader->dest_mac[2],
			ethHeader->dest_mac[3], ethHeader->dest_mac[4], ethHeader->dest_mac[5],
			ntohs(ethHeader->type));

		// IP 헤더 파싱 및 출력
		//INET_ADDRSTRLEN은 IPv4 주소 문자열의 최대 길이를 정의하는 상수
		//srcIPStr과 destIPStr은 변환된 IP주소를 저장할 버퍼.
		char srcIPStr[INET_ADDRSTRLEN];
		char destIPStr[INET_ADDRSTRLEN];
		//inet_ntop함수를 사용하여 ip_srcaddr,up_destaddr에 저장된 IP 주소를 사람이 읽을 수 있는 심진수 형식으로 변환하여 srcIPStr, destIPStr에 저장.
		inet_ntop(AF_INET, &(ipHeader->ip_srcaddr), srcIPStr, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ipHeader->ip_destaddr), destIPStr, INET_ADDRSTRLEN);

		//ntohs(네트워크 바이트 순서에서 호스트 바이트 순서로 변환)
		CString ipDetails;
		ipDetails.Format(_T("IP Header:\r\n")
			_T(" - Version: %d\r\n")
			_T(" - Header Length: %d bytes\r\n")
			_T(" - Type of Service: %d\r\n")
			_T(" - Total Length: %d bytes\r\n")
			_T(" - Identification: %d\r\n")
			_T(" - Flags: %d\r\n")
			_T(" - Fragment Offset: %d\r\n")
			_T(" - Time to Live: %d\r\n")
			_T(" - Protocol: %d\r\n")
			_T(" - Header Checksum: %04X\r\n")
			_T(" - Source IP: %S\r\n")
			_T(" - Destination IP: %S\r\n"),
			ipHeader->ip_version,
			ipHeader->ip_header_len * 4,
			ipHeader->ip_tos,
			ntohs(ipHeader->ip_total_length),
			ntohs(ipHeader->ip_id),
			ipHeader->ip_flags,
			ntohs(ipHeader->ip_offset),
			ipHeader->ip_ttl,
			ipHeader->ip_protocol,
			ntohs(ipHeader->ip_checksum),
			srcIPStr, destIPStr);

		// TCP 헤더 파싱 및 출력
		CString tcpDetails;
		tcpDetails.Format(_T("TCP Header:\r\n")
			_T(" - Source Port: %d\r\n")
			_T(" - Destination Port: %d\r\n")
			_T(" - Sequence Number: %u\r\n")
			_T(" - Acknowledgment Number: %u\r\n")
			_T(" - Header Length: %d\r\n")
			_T(" - Flags: %02X\r\n")
			_T(" - Window: %d\r\n")
			_T(" - Checksum: %04X\r\n")
			_T(" - Urgent Pointer: %d\r\n"),
			ntohs(tcpHeader->source_port), ntohs(tcpHeader->dest_port), ntohl(tcpHeader->sequence),
			ntohl(tcpHeader->acknowledge), tcpHeader->data_offset * 4, tcpHeader->flags,
			ntohs(tcpHeader->window), ntohs(tcpHeader->checksum), ntohs(tcpHeader->urgent_pointer));

		// 최종적으로 Edit 컨트롤에 출력
		CString details = ethernetDetails + _T("\r\n") + ipDetails + _T("\r\n") + tcpDetails;
		m_editPacketDetails.SetWindowText(details);
		//옆 Edit 창에 16진수 원문 전달.
		DisplayHexDump(pkt_data, pkt_length);
	}
	*pResult = 0;
}


void CPacketAnalsysv2Dlg::OnBnClickedCaptureButton()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	if (!m_bCapturing) {
		m_bCapturing = true;	//캡쳐 플래그 설정.
		m_pCaptureThread = AfxBeginThread(CaptureThreadFunc, this);	//캡처 스레드 시작.
	}
}

void CPacketAnalsysv2Dlg::OnBnClickedStopButton()
{
	//캡처 중지 버튼 클릭
	if (m_bCapturing && m_pCaptureThread != nullptr)
	{
		m_bCapturing = FALSE; // 캡처 중지 신호

		// 비동기적으로 스레드가 종료되었는지 확인
		if (WaitForSingleObject(m_pCaptureThread->m_hThread, 0) == WAIT_OBJECT_0)
		{
			// 스레드가 이미 종료됨
			delete m_pCaptureThread;
			m_pCaptureThread = nullptr;
			AfxMessageBox(_T("Capture stopped."));
		}
		else
		{
			// 스레드가 아직 종료되지 않았으면 UI 응답을 유지하면서 스레드가 종료되도록 대기
			SetTimer(1, 100, nullptr); // 1번 타이머를 설정하여 일정 시간마다 종료 확인
		}
		//EnableWindow(FALSE); //UI 비활성화(중지 버튼 클릭 시 다른 입력 방지)

		//WaitForSingleObject(m_pCaptureThread->m_hThread, INFINITE);	//스레드가 종료될 때까지 대기.

		//// 스레드 종료 후 스레드 해제
		//delete m_pCaptureThread;
		//m_pCaptureThread = nullptr;

		//// UI 다시 활성화
		//EnableWindow(TRUE);

		//// 사용자 알림
		//AfxMessageBox(_T("Capture stopped."));
	}
}

void CPacketAnalsysv2Dlg::AddPacketToList(int packetNum, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	//캡처한 패킷 데이터를 백터에 저장.
	m_packetStorage.push_back(std::vector<u_char>(pkt_data, pkt_data + header->len));
	// 패킷 번호 삽입
	CString packetNumStr;
	packetNumStr.Format(_T("%d"), packetNum);
	int nItem = m_listCtrl.InsertItem(packetNum - 1, packetNumStr);

	//// 패킷 시간을 포맷하여 문자열로 변환
	//time_t rawTime = header->ts.tv_sec;
	//struct tm timeInfo;
	//char buffer[64];
	//localtime_s(&timeInfo, &rawTime);
	//strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeInfo);

	////패킷 시간을 문자열로 변환하여 리스트에 추가
	//CString timeStr;
	//timeStr.Format(_T("%lld"), static_cast<long long>(header->ts.tv_sec));
	//m_listCtrl.SetItemText(nItem, 1, timeStr);
	time_t rawTime = header->ts.tv_sec;	//Unix timestamp 1970년 1월 1일 부터 경과한 초를 나타냄.
	if (rawTime > 0) { // 시간 값이 유효한 경우에만 변환
		struct tm timeInfo;
		char buffer[64];
		localtime_s(&timeInfo, &rawTime);	//rawTime값을 구조체 tm으로 변환.
		strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeInfo);	//tm 구조체를 통해 실제 날짜와 시간의 문자열로 변환하고 버퍼에 저장.

		CString timeStr;
		timeStr.Format(_T("%S"), buffer);	//버퍼를 timeStr에 저장.
		m_listCtrl.SetItemText(nItem, 1, timeStr);
	}
	else {
		// 시간 값이 비정상적인 경우
		m_listCtrl.SetItemText(nItem, 1, _T("Invalid time"));
	}
	// 패킷 데이터를 lParam에 저장
	m_listCtrl.SetItemData(nItem, reinterpret_cast<DWORD_PTR>(pkt_data));

	// IP 헤더를 Ethernet 헤더(14바이트) 이후로 파싱
	const ip_header* ipHeader = reinterpret_cast<const ip_header*>(pkt_data + 14);
	char srcIPStr[INET_ADDRSTRLEN];
	char destIPStr[INET_ADDRSTRLEN];
	//inet_ntoa는 사용 권장 X  inet_ntop를 사용 권장.
	inet_ntop(AF_INET, &(ipHeader->ip_srcaddr), srcIPStr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ipHeader->ip_destaddr), destIPStr, INET_ADDRSTRLEN);
	CString srcIP, destIP, protocol;
	srcIP.Format(_T("%S"), srcIPStr);
	destIP.Format(_T("%S"), destIPStr);
	// 프로토콜 필드를 해석
	switch (ipHeader->ip_protocol) {
	case 6:
		protocol = _T("TCP");
		break;
	case 17:
		protocol = _T("UDP");
		break;
	case 1:
		protocol = _T("ICMP");
		break;
	default:
		protocol.Format(_T("Unknown (%d)"), ipHeader->ip_protocol);
		break;
	}
	m_listCtrl.SetItemText(nItem, 2, srcIP);
	m_listCtrl.SetItemText(nItem, 3, destIP);
	m_listCtrl.SetItemText(nItem, 4, protocol);

	// 패킷 길이 설정
	CString lengthStr;
	lengthStr.Format(_T("%d bytes"), header->len);
	m_listCtrl.SetItemText(nItem, 5, lengthStr);

	// Info는 간단한 설명
	CString info;
	info.Format(_T("Captured packet of length %d"), header->len);
	m_listCtrl.SetItemText(nItem, 6, info);

	// 자동 스크롤
	if (m_bAutoScroll) {
		m_listCtrl.EnsureVisible(nItem, FALSE);
	}
}




// 쓰레드 함수 정의
UINT CPacketAnalsysv2Dlg::CaptureThreadFunc(LPVOID pParam)
{
	CPacketAnalsysv2Dlg* pDlg = reinterpret_cast<CPacketAnalsysv2Dlg*>(pParam);
	pcap_if_t* alldevs = nullptr;
	pcap_if_t* device = nullptr;
	char errbuf[PCAP_ERRBUF_SIZE];
	//네트워크 디바이스 검색
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		AfxMessageBox(_T("Error finding devices"));
		return 1;
	}
	//특정 디바이스 연결(ex 현재 이더넷 연결된 네트워크 인터페이스 이름)
	//"\\Device\\NPF_{B0AFD485-E0B1-45F1-A9E5-C7B445D9F92E}"
	for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
		if (CString(d->name) == (pDlg->m_selectedInterface)) {
			device = d;
			break;
		}
	}

	//디바이스가 없는 경우 에러 처리.
	if (device == nullptr) {
		AfxMessageBox(_T("Desired device not found"));
		pcap_freealldevs(alldevs);
		return 1;
	}
	// 디바이스 열기
	pcap_t* handle = pcap_open_live(device->name, 65536, 1, 5000, errbuf);
	if (!handle) {
		AfxMessageBox(_T("Could not open device"));
		pcap_freealldevs(alldevs);
		return 1;
	}

	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int packetCount = 0;

	while (pDlg->m_bCapturing) {
		int res = pcap_next_ex(handle, &header, &pkt_data);
		if (res == 1) {
			packetCount++;
			pDlg->AddPacketToList(packetCount, header, pkt_data);	//캡처한 패킷을 List에 출력
		}
		else if (res == -1) {
			CString errorMsg;
			errorMsg.Format(_T("Error capturing packet: %S"), pcap_geterr(handle));
			AfxMessageBox(errorMsg);
			break;
		}
	}
	// 자원해제
	pcap_close(handle);
	pcap_freealldevs(alldevs);
	return 0;
}

// 타이머 이벤트 핸들러 추가
void CPacketAnalsysv2Dlg::OnTimer(UINT_PTR nIDEvent)
{
	if (nIDEvent == 1 && m_pCaptureThread != nullptr)
	{
		if (WaitForSingleObject(m_pCaptureThread->m_hThread, 0) == WAIT_OBJECT_0)
		{
			// 스레드가 종료됨
			delete m_pCaptureThread;
			m_pCaptureThread = nullptr;
			KillTimer(1); // 타이머 정지
			AfxMessageBox(_T("Capture stopped."));
		}
	}

	CDialogEx::OnTimer(nIDEvent);
}


void CPacketAnalsysv2Dlg::OnEnChangePacketDetails()
{
	// TODO:  RICHEDIT 컨트롤인 경우, 이 컨트롤은
	// CDialogEx::OnInitDialog() 함수를 재지정 
	//하고 마스크에 OR 연산하여 설정된 ENM_CHANGE 플래그를 지정하여 CRichEditCtrl().SetEventMask()를 호출하지 않으면
	// 이 알림 메시지를 보내지 않습니다.

	// TODO:  여기에 컨트롤 알림 처리기 코드를 추가합니다.
}

void CPacketAnalsysv2Dlg::DisplayHexDump(const u_char* pkt_data, int len)
{
	CString hexDump;
	int lineWidth = 16;

	for (int i = 0; i < len; i += lineWidth) {
		CString hexLine;

		// 16진수 출력
		for (int j = 0; j < lineWidth; ++j) {
			if (i + j < len) {
				CString byteStr;
				byteStr.Format(_T("%02X "), pkt_data[i + j]);
				hexLine += byteStr;
			}
			else {
				hexLine += _T("   ");
			}
		}

		CString line;
		line.Format(_T("%04X  %s\r\n"), i, hexLine);
		hexDump += line;
	}

	m_editPacketHexDump.SetWindowText(hexDump);
}


void CPacketAnalsysv2Dlg::OnBnClickedConnectButton()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	// 네트워크 인터페이스 선택 다이얼로그 생성
	CNetworkInterfaceDlg interfaceDlg;
	// 다이얼로그 표시, 사용자가 OK 버튼을 눌렀을 때 계속 진행
	if (interfaceDlg.DoModal() == IDOK) {
		// 네트워크 인터페이스 선택 후 처리
		m_selectedInterface = interfaceDlg.GetSelectedInterface();
		TRACE(_T("Value of x: %s\n"), m_selectedInterface);
		if (!m_selectedInterface.IsEmpty()) {
			AfxMessageBox(_T("네트워크 인터페이스가 선택되었습니다."));
		}
		else {
			AfxMessageBox(_T("선택한 네트워크 인터페이스가 없습니다."));
		}
		UpdateCaptureButtonState();
	}
}

void CPacketAnalsysv2Dlg::UpdateCaptureButtonState() {
	BOOL enableCaptureButton = !m_selectedInterface.IsEmpty();
	TRACE(_T("Boolean value: %s\n"), enableCaptureButton ? _T("TRUE") : _T("FALSE"));
	GetDlgItem(IDC_CAPTURE_BUTTON)->EnableWindow(enableCaptureButton);
}
