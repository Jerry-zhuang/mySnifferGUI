#pragma execution_character_set("utf-8")

#include <QtWidgets/QMainWindow>
#include <QGroupBox>
#include <QComboBox>
#include <QPushButton>
#include <QGridLayout>
#include <QLineEdit>
#include <QLayout>
#include <QSplitter>
#include <QLabel>
#include <QTextEdit>
#include <QVector>
#include "ui_mySnifferGUI.h"
#include "mySnifferCMD.h"
#include "DataPacket.h"
#include "subThread.h"
#include "pcap.h"

class mySnifferGUI : public QMainWindow
{
    Q_OBJECT

public:
    mySnifferGUI(QWidget *parent = Q_NULLPTR);
    ~mySnifferGUI();

    void addEthernetTree();     // mac层的TreeWigetItem
    int addIPTree();          // Tcp的TreeWidgetItem

    void initAdapter();
    int capture();

    //void initUI();
    //void initGroup();
    //void initSplitter();
    //
    //// ----------初始化网卡Group-----------
    //void initAdapterGroup();
    //void initAdapterBox();
    //void initStartAndStopBtn();
    // ------------------------------------

    // ------------------------------------
    // void initIPGroup();
    // ------------------------------------

private:
    Ui::mySnifferGUIClass ui;

    // -----------------------------
    pcap_if_t* allAdapter;  // 网卡列表
    pcap_if_t* adapter;     // 网卡
    pcap_t* openAdapter;    // 打开网卡

    QVector<DataPacket> pData;  //  封装数据的容器
    int countNumber;            // 数据的数量
    int selectRow;              // 选择的行号
    char errbuf[PCAP_ERRBUF_SIZE];  // error

    //QWidget* centralW;   // 中心窗口

    //QGridLayout* layout;    // 整体网格布局
    //QVBoxLayout* groupBoxLayout;    // 右侧选项栏的布局

    //// -----------------------------------------------------------------
    //QVBoxLayout* adapterGroupLayout;    // 网卡group中的布局

    //QGroupBox* adapterGroup;  //选择网卡的Group

    //QComboBox* adapterBox;  // 网卡选择抽屉
    //QPushButton* startBtn;  // 开始按钮
    //QPushButton* stopBtn;   // 停止按钮
    //QHBoxLayout* startAndStopLayout;    // 开始和停止按钮的布局
    //// -----------------------------------------------------------------
    //// -----------------------------------------------------------------
    //QVBoxLayout* ipGroupLayout;
    //QGroupBox* ipGroup;   // 选择ip的Group
    //QLineEdit* ipInput;   // IP输入
    //// -----------------------------------------------------------------

    //QGroupBox* wafGroup;  // 攻击查询的Group

    //// -----------------------------------------------------------------
    //QSplitter* splitter;
    //QWidget* packetWidget;
    //QWidget* inforWidget;

    //QWidget* nullW;

private slots:
    void on_adapterBox_currentIndexChanged(int index);
    void on_tableWidget_cellClicked(int row, int column);

public slots:
    void HandleMessage(DataPacket data);
};
