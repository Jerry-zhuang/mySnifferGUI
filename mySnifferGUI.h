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

    void addEthernetTree();     // mac���TreeWigetItem
    int addIPTree();          // Tcp��TreeWidgetItem

    void initAdapter();
    int capture();

    //void initUI();
    //void initGroup();
    //void initSplitter();
    //
    //// ----------��ʼ������Group-----------
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
    pcap_if_t* allAdapter;  // �����б�
    pcap_if_t* adapter;     // ����
    pcap_t* openAdapter;    // ������

    QVector<DataPacket> pData;  //  ��װ���ݵ�����
    int countNumber;            // ���ݵ�����
    int selectRow;              // ѡ����к�
    char errbuf[PCAP_ERRBUF_SIZE];  // error

    //QWidget* centralW;   // ���Ĵ���

    //QGridLayout* layout;    // �������񲼾�
    //QVBoxLayout* groupBoxLayout;    // �Ҳ�ѡ�����Ĳ���

    //// -----------------------------------------------------------------
    //QVBoxLayout* adapterGroupLayout;    // ����group�еĲ���

    //QGroupBox* adapterGroup;  //ѡ��������Group

    //QComboBox* adapterBox;  // ����ѡ�����
    //QPushButton* startBtn;  // ��ʼ��ť
    //QPushButton* stopBtn;   // ֹͣ��ť
    //QHBoxLayout* startAndStopLayout;    // ��ʼ��ֹͣ��ť�Ĳ���
    //// -----------------------------------------------------------------
    //// -----------------------------------------------------------------
    //QVBoxLayout* ipGroupLayout;
    //QGroupBox* ipGroup;   // ѡ��ip��Group
    //QLineEdit* ipInput;   // IP����
    //// -----------------------------------------------------------------

    //QGroupBox* wafGroup;  // ������ѯ��Group

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
