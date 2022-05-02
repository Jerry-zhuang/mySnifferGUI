#include "mySnifferGUI.h"

/**
 * @brief 构造函数
 * @param parent 父窗口
*/
mySnifferGUI::mySnifferGUI(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    ui.tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    statusBar()->showMessage("Welcome to mySniffer!");
    ui.stopBtn->setEnabled(false);
    countNumber = 0;    // 初始化行数为0
    selectRow = -1;     // 初始化被选中的行号为-1，既未被选中
    initAdapter();

    subThread* thread = new subThread();

    static bool flag = false;
    // 开始按钮的连接
    connect(ui.startBtn, &QPushButton::clicked, this, [=](){
        if (flag == false) {
            flag = !flag;
            /* 初始化pData */
            countNumber = 0;
            ui.tableWidget->clearContents();
            ui.tableWidget->setRowCount(countNumber);

            int dataSize = this->pData.size();
            for (int i = 0; i < dataSize; i++) {
                // qDebug() << i;
                free((char*)(this->pData[i].pkt_content));
                this->pData[i].pkt_content = nullptr;
            }
            QVector<DataPacket>().swap(pData);
            /* END */

            int res = capture();
            if (res != -1 && openAdapter) {

                thread->setOpenAdapter(openAdapter);
                thread->setFlag();
                thread->start();
                ui.adapterBox->setEnabled(false);
                ui.startBtn->setEnabled(false);
                ui.stopBtn->setEnabled(true);
            }
            else {
                flag = !flag;
                countNumber = 0;
            }
        }
        });
    // 暂停按钮的连接
    connect(ui.stopBtn, &QPushButton::clicked, this, [=]() {
        if (flag == true) {
            flag = !flag;
            thread->resetFlag();
            thread->quit();
            thread->wait();
            ui.adapterBox->setEnabled(true);
            ui.startBtn->setEnabled(true);
            ui.stopBtn->setEnabled(false);
            pcap_close(openAdapter);
            openAdapter = NULL;
        }
        });
    // 子进程与主进程的数据传输连接
    connect(thread, &subThread::send, this, &mySnifferGUI::HandleMessage);
    
    QStringList title = { "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info" };
    ui.tableWidget->setColumnCount(7);
    ui.tableWidget->setHorizontalHeaderLabels(title);
    ui.tableWidget->setColumnWidth(0, 50);
    ui.tableWidget->setColumnWidth(1, 150);
    ui.tableWidget->setColumnWidth(2, 200);
    ui.tableWidget->setColumnWidth(3, 200);
    ui.tableWidget->setColumnWidth(4, 100);
    ui.tableWidget->setColumnWidth(5, 100);
    ui.tableWidget->setColumnWidth(6, 1000);

    ui.tableWidget->setShowGrid(false);
    ui.tableWidget->verticalHeader()->setVisible(false);
    ui.tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui.treeWidget->setHeaderHidden(true);


}

/**
 * @brief 析构函数
*/
mySnifferGUI::~mySnifferGUI()
{
    int dataSize = pData.size();
    for (int i = 0; i < dataSize; i++) {
        free((char*)(this->pData[i].pkt_content));
        this->pData[i].pkt_content = NULL;
    }
    QVector<DataPacket>().swap(pData);

}

/**
 * @brief 初始化网卡抽屉的内容
*/
void mySnifferGUI::initAdapter() {

    // 是否找到网卡
    int flag = pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allAdapter, errbuf);  

    if (flag == -1) {
        ui.adapterBox->addItem("[ERROR] 无法获取网卡 ");
    }
    else {
        ui.adapterBox->clear();
        ui.adapterBox->addItem(QString::fromStdString("请选择网卡"));
        for (adapter = allAdapter; adapter != NULL; adapter = adapter->next) {
            string desc = adapter->description;
            int pos_1 = desc.find("'");
            int pos_2 = desc.find_last_of("'");
            QString name = QString::fromStdString(desc.substr(pos_1 + 1, pos_2 - pos_1 - 1));
            ui.adapterBox->addItem(name);
        }
    }
}

/**
 * @brief 网卡选择的槽函数
 * @param index 
*/
void mySnifferGUI::on_adapterBox_currentIndexChanged(int index) {
    int i = 0;
    for (adapter = allAdapter; i < index - 1; i++, adapter = adapter->next);
    return;
}

/**
 * @brief 数据包详细信息的槽函数
 * @param row 
 * @param column 
*/
void mySnifferGUI::on_tableWidget_cellClicked(int row, int column)
{
    if (row == selectRow || row < 0) {  // 当重复选择或未选择，直接return
        return;
    }
    else {
        ui.treeWidget->clear(); // 清除treeWidget
        selectRow = row;    
        if (selectRow < 0 || selectRow > countNumber)
            return;

        /* 数据链路层的相关信息输出 */
        addEthernetTree();
        
        QString packageType = pData[selectRow].getPacketType();
        if (packageType == "ARP") {   // ARP
            return;
        }
        else {
            /* IPv4相关信息输出 */
            int ipDataLength = addIPTree();
            if (packageType == "TCP") {
                QString srcPort = pData[selectRow].getTCPSrcPort();
                QString dstPort = pData[selectRow].getTCPDstPort();
                QString seq = pData[selectRow].getTCPSeq();
                QString ack = pData[selectRow].getTCPAck();
                int lenRaw = pData[selectRow].getTCPRawHeaderLength().toUtf8().toInt();
                QString tcpDataLength = QString::number(ipDataLength - lenRaw);
                QString len = pData[selectRow].getTCPHeaderLength();
                /* TCP Flags Tree*/
                QString tcpFlags = pData[selectRow].getTCPFlags();
                QString URG = pData[selectRow].getTCPFlagsURG();    if ( URG == "1") tcpFlags += " (URG)";
                QString ACK = pData[selectRow].getTCPFlagsACK();    if ( ACK == "1") tcpFlags += " (ACK)";
                QString PSH = pData[selectRow].getTCPFlagsPSH();    if ( PSH == "1") tcpFlags += " (PSH)";
                QString RST = pData[selectRow].getTCPFlagsRST();    if ( RST == "1") tcpFlags += " (RST)";
                QString SYN = pData[selectRow].getTCPFlagsSYN();    if ( SYN == "1") tcpFlags += " (SYN)";
                QString FIN = pData[selectRow].getTCPFlagsFIN();    if ( FIN == "1") tcpFlags += " (FIN)";
                QTreeWidgetItem* tcpFlagsTree = new QTreeWidgetItem(QStringList() << "Flags: " + tcpFlags);
                tcpFlagsTree->addChild(new QTreeWidgetItem(QStringList() << ".." + URG + ". .... Urgent: " + (URG == "1" ? "Set" : "Not set")));
                tcpFlagsTree->addChild(new QTreeWidgetItem(QStringList() << "..." + ACK + " .... Acknowledgment: " + (ACK == "1" ? "Set" : "Not set")));
                tcpFlagsTree->addChild(new QTreeWidgetItem(QStringList() << ".... " + PSH + "... Push: " + (PSH == "1" ? "Set" : "Not set")));
                tcpFlagsTree->addChild(new QTreeWidgetItem(QStringList() << ".... ." + RST + ".. Reset: " + (RST == "1" ? "Set" : "Not set")));
                tcpFlagsTree->addChild(new QTreeWidgetItem(QStringList() << ".... .." + SYN + ". Syn: " + (SYN == "1" ? "Set" : "Not set")));
                tcpFlagsTree->addChild(new QTreeWidgetItem(QStringList() << ".... ..." + FIN + " Fin: " + (FIN == "1" ? "Set" : "Not set")));
                /* TCP Flags Tree END*/
                QString tcpWindow = pData[selectRow].getTCPWindows();
                QString tcpCheckSum = pData[selectRow].getTCPCheckSum();
                QString urgentPointer = pData[selectRow].getTCPUrgenPointer();

                QTreeWidgetItem* item = new QTreeWidgetItem(QStringList() << "Transmission Control Protocol, Src Port: " + srcPort + ", Dst Port: " + dstPort + ", Seq: "+ seq + ", Ack： " + ack + ", Len: " + tcpDataLength);
                ui.treeWidget->addTopLevelItem(item);

                item->addChild(new QTreeWidgetItem(QStringList() << "Source Port : " + srcPort));
                item->addChild(new QTreeWidgetItem(QStringList() << "Destination Port : " + dstPort));
                if (SYN == "1")
                    item->addChild(new QTreeWidgetItem(QStringList() << "Sequence Number : 0 (relertive sequence number)"));
                else
                    item->addChild(new QTreeWidgetItem(QStringList() << "Sequence Number : 暂时没写"));
                item->addChild(new QTreeWidgetItem(QStringList() << "Sequence Number (raw) : " + seq));
                if (SYN == "1" && ACK == "1")
                    item->addChild(new QTreeWidgetItem(QStringList() << "Acknowledgement Number : 1 (relertive sequence number)"));
                else
                    item->addChild(new QTreeWidgetItem(QStringList() << "Acknowledgement Number : 暂时没写"));
                item->addChild(new QTreeWidgetItem(QStringList() << "Acknowledgement Number (raw) : " + ack));
                QString binLenRaw = QString::number(lenRaw, 2);
                while (binLenRaw.size() < 4) binLenRaw = "0" + binLenRaw;
                item->addChild(new QTreeWidgetItem(QStringList() << binLenRaw + " ....  Header Length : " + len));
                item->addChild(tcpFlagsTree);
                item->addChild(new QTreeWidgetItem(QStringList() << "Window : " + tcpWindow));
                item->addChild(new QTreeWidgetItem(QStringList() << "CheckSum : " + tcpCheckSum));
                item->addChild(new QTreeWidgetItem(QStringList() << "Urgen pointer : " + urgentPointer));
                if ((lenRaw * 4) > 20)
                    item->addChild(new QTreeWidgetItem(QStringList() << "[TODO] 这个TCP包有后续的扩展选项，但是我还没写罢了"));
                if(tcpDataLength.toUtf8().toInt() > 0)
                    item->addChild(new QTreeWidgetItem(QStringList() << "TCP payload (" + tcpDataLength + " bytes)"));
            }
        }
    }
}

/**
 * @brief 数据链路层的TreeItem
*/
void mySnifferGUI::addEthernetTree() {
    /* 数据链路层的相关信息输出 */
    QString srcMac = pData[selectRow].getSrcMacAddr();
    QString dstMac = pData[selectRow].getDstMacAddr();
    QString type = pData[selectRow].getMacType();
    QTreeWidgetItem* item1 = new QTreeWidgetItem(QStringList() << "Ethernet, Src: " + srcMac + ", Dst: " + dstMac);
    ui.treeWidget->addTopLevelItem(item1);
    item1->addChild(new QTreeWidgetItem(QStringList() << "Destination: " + dstMac));
    item1->addChild(new QTreeWidgetItem(QStringList() << "Source: " + srcMac));
    item1->addChild(new QTreeWidgetItem(QStringList() << "Type: " + type));
}

/**
 * @brief IP的TreeItem
 * @return IP的数据段长度
*/
int mySnifferGUI::addIPTree() {
    QString srcIP = pData[selectRow].getSrcIPAddr();
    QString dstIP = pData[selectRow].getDstIPAddr();

    QTreeWidgetItem* item2 = new QTreeWidgetItem(QStringList() << "Internet Protocol version 4, Src:" + srcIP + ", Dst:" + dstIP);
    ui.treeWidget->addTopLevelItem(item2);

    QString ipVersion = pData[selectRow].getIPVersion();
    QString ipHeaderLength = pData[selectRow].getIPHeaderLength();
    QString ipTOS = pData[selectRow].getIPTOS();
    QString ipTotalLength = pData[selectRow].getIPTotalLength();
    QString ipIdentification = pData[selectRow].getIPIdentification();
    /* Flags tree */
    QString ipFlags = pData[selectRow].getIPFlags();
    QString ipFlagsRB = pData[selectRow].getIPFlagsRB();
    QString ipFlagsDF = pData[selectRow].getIPFlagsDF();
    QString ipFlagsMF = pData[selectRow].getIPFlagsMF();
    if (ipFlagsRB == "1")    ipFlags += ", Reserved bit";
    else if (ipFlagsDF == "1")  ipFlags += ", Don't fragment";
    else if (ipFlagsMF == "1")  ipFlags += ", More fragments";
    QTreeWidgetItem* flagsTree = new QTreeWidgetItem(QStringList() << "Flags: " + ipFlags);
    flagsTree->addChild(new QTreeWidgetItem(QStringList() << ipFlagsRB
        + "... .... = Reserved bit: "
        + (ipFlagsRB == "1" ? "Set" : "Not Set")));
    flagsTree->addChild(new QTreeWidgetItem(QStringList() << "." + ipFlagsDF
        + ".. .... = Don't fragment: "
        + (ipFlagsDF == "1" ? "Set" : "Not Set")));
    flagsTree->addChild(new QTreeWidgetItem(QStringList() << ".." + ipFlagsMF
        + ". .... = More fragment: "
        + (ipFlagsMF == "1" ? "Set" : "Not Set")));
    /* Flags tree END */
    QString ipFragmentOffset = pData[selectRow].getIPFragmentOffset();
    QString ipTTL = pData[selectRow].getIPTimeToLive();
    QString ipProtocol = pData[selectRow].getIPProtocol();
    QString ipCheckSum = pData[selectRow].getIPCheckSum();

    item2->addChild(new QTreeWidgetItem(QStringList() << "0100 . . . . = Version: " + ipVersion));
    item2->addChild(new QTreeWidgetItem(QStringList() << ". . . . 0101 = Header Length: " + ipHeaderLength));
    item2->addChild(new QTreeWidgetItem(QStringList() << "TOS: " + ipTOS));
    item2->addChild(new QTreeWidgetItem(QStringList() << "Total Length: " + ipTotalLength));
    item2->addChild(new QTreeWidgetItem(QStringList() << "Identification: " + ipIdentification));
    item2->addChild(flagsTree);
    item2->addChild(new QTreeWidgetItem(QStringList() << "Fragment Offset: " + ipFragmentOffset));
    item2->addChild(new QTreeWidgetItem(QStringList() << "Time to Live: " + ipTTL));
    item2->addChild(new QTreeWidgetItem(QStringList() << "Protocol: " + ipProtocol));
    item2->addChild(new QTreeWidgetItem(QStringList() << "Header Checksum: 0x" + ipCheckSum));
    item2->addChild(new QTreeWidgetItem(QStringList() << "Source Address: " + srcIP));
    item2->addChild(new QTreeWidgetItem(QStringList() << "Destination Address: " + dstIP));

    return ipTotalLength.toUtf8().toInt();
}

/**
 * @brief 捕获数据包
 * @return 
*/
int mySnifferGUI::capture() {
    if (adapter != NULL) {
        openAdapter = pcap_open_live(adapter->name, 65536, 1, 1000, errbuf);
        if (openAdapter != NULL) {
            if (pcap_datalink(openAdapter) == DLT_EN10MB) {
                statusBar()->showMessage(adapter->description);
                statusBar()->show();
            }
            else {
                pcap_close(openAdapter);
                pcap_freealldevs(allAdapter);
                openAdapter = NULL;
                adapter = NULL;
                return -1;
            }
        }
        else {
            pcap_freealldevs(allAdapter);
            adapter = NULL;
            return -1;
        }
    }
    else {
        return -1;
    }
}

/**
 * @brief 信息处理函数
 * @param data 
*/
void mySnifferGUI::HandleMessage(DataPacket data) {
    ui.tableWidget->insertRow(countNumber);
    this->pData.push_back(data);
    QString type = data.getPacketType();
    
    QColor color;
    if (type == "TCP")
        color = QColor(231, 230, 255);
    else if (type == "UDP")
        color = QColor(218, 238, 255);
    else if (type == "ARP")
        color = QColor(250, 240, 215);
    else if (type == "DNS")
        color = QColor(218, 238, 255);
    else 
        color = QColor(160, 160, 160);

    ui.tableWidget->setItem(countNumber, 0, new QTableWidgetItem(QString::number(countNumber)));
    ui.tableWidget->setItem(countNumber, 1, new QTableWidgetItem(data.getTimeStamp()));
    ui.tableWidget->setItem(countNumber, 2, new QTableWidgetItem(data.getSource()));
    ui.tableWidget->setItem(countNumber, 3, new QTableWidgetItem(data.getDestination()));
    ui.tableWidget->setItem(countNumber, 4, new QTableWidgetItem(type));
    ui.tableWidget->setItem(countNumber, 5, new QTableWidgetItem(data.getDataLength()));
    ui.tableWidget->setItem(countNumber, 6, new QTableWidgetItem(data.getPacketInfo()));
    for (int i = 0; i < 7; i++)
        ui.tableWidget->item(countNumber, i)->setBackgroundColor(color);
    countNumber++;
    // qDebug() << data.getTimeStamp() << " " << data.getPacketInfo();
}
































































//
///**
// * @brief 主UI初始化
//*/
//void mySnifferGUI::initUI() {
//    
//	/* 设置中控窗口 */
//	centralW = new QWidget(this);
//	this->setCentralWidget(centralW);
//
//	/* 布局设置 */
//    layout = new QGridLayout(centralW);   // 网格布局
//
//	// 左侧的GroupBox的布局设置
//    initGroup();
//	layout->addLayout(groupBoxLayout, 0, 0, 1, 1);
//	// this->setLayout(layout);
//
//	// 右侧窗口的布局设置
//	// nullW = new QWidget();	// 没有窗口，暂时拿一个占位置
//	initSplitter();
//	layout->addWidget(splitter, 0, 1, 1, 3);
//	// layout->addWidget(nullW, 3, 3);
//
//	centralW->setLayout(layout);
//}
//
///**
// * @brief 左侧GroupBox的布局初始化
//*/
//void mySnifferGUI::initGroup() {
//
//	/* 设置左侧GroupBox的布局 */
//    groupBoxLayout = new QVBoxLayout(centralW);   // group的垂直布局
//
//	initAdapterGroup();	// 初始化网卡Group
//	initIPGroup();
//
//	/* 添加布局中的组件 */
//	groupBoxLayout->addWidget(adapterGroup);
//	groupBoxLayout->addWidget(ipGroup);
//
//	groupBoxLayout->addStretch();
//}
//
///**
// * @brief 初始化右侧的分割窗口
//*/
//void mySnifferGUI::initSplitter() {
//	splitter = new QSplitter(Qt::Vertical, centralW);
//	splitter->setOpaqueResize(TRUE);
//
//	packetWidget = new QWidget(splitter);
//	QTextEdit* topLeft = new QTextEdit(QObject::tr("Left Widget"), packetWidget);
//	inforWidget = new QWidget(splitter);
//	QTextEdit* downLeft = new QTextEdit(QObject::tr("Left Widget"), inforWidget);
//}
//
///**
// * @brief 初始化网卡Group
//*/
//void mySnifferGUI::initAdapterGroup() {
//	/* 网卡GroupBox的初始化 */
//	adapterGroup = new QGroupBox("网卡");
//	adapterGroupLayout = new QVBoxLayout;
//
//	initAdapterBox();	// 初始化网卡抽屉
//	initStartAndStopBtn();	// 初始化开始停止按钮
//
//	adapterGroupLayout->addWidget(adapterBox);	// 在网卡Group布局中添加网卡抽屉
//	adapterGroupLayout->addLayout(startAndStopLayout);	// 在网卡Group布局中添加按钮
//
//	adapterGroup->setLayout(adapterGroupLayout);
//	/* 网卡GroupBox的初始化 END */
//}
//
///**
// * @brief 初始化IPGroup
//*/
//void mySnifferGUI::initIPGroup() {
//	ipGroup = new QGroupBox("IP筛选");
//	ipGroupLayout = new QVBoxLayout;
//
//	ipInput = new QLineEdit();
//	// ipInput->setEchoMode(QLineEdit::Normal);
//	ipInput->setPlaceholderText("xxx.xxx.xxx.xxx");
//	ipInput->setSizePolicy(QSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed));
//
//	ipGroupLayout->addWidget(ipInput, 0);
//
//	ipGroup->setLayout(ipGroupLayout);
//}
//
///**
// * @brief 初始化网卡抽屉
//*/
//void mySnifferGUI::initAdapterBox() {
//
//    adapterBox = new QComboBox(adapterGroup);   // 网卡抽屉
//
//	pcap_if_t* alladapters = getDeviceList();	// 网卡指针
//	pcap_if_t* d;	// 临时网卡指针
//	string desc, name = "";
//	int i = 0, pos_1, pos_2;
//	for (d = alladapters; d != NULL; d = d->next) {
//		if (i > 19)
//			break;
//		// 截取网卡的名称
//		desc = d->description;
//		pos_1 = desc.find("'");
//		pos_2 = desc.find_last_of("'");
//		name = desc.substr(pos_1 + 1, pos_2 - pos_1 - 1);
//
//		//	添加标签到布局中
//		adapterBox->addItem(QString::fromStdString(name));
//		i++;
//	}
//}
//
///**
// * @brief 初始化开始暂停按钮
//*/
//void mySnifferGUI::initStartAndStopBtn() {
//	startAndStopLayout = new QHBoxLayout;
//
//	startBtn = new QPushButton("开始", adapterGroup);
//	stopBtn = new QPushButton("暂停", adapterGroup);
//
//	startAndStopLayout->addWidget(startBtn);
//	startAndStopLayout->addWidget(stopBtn);
//}
