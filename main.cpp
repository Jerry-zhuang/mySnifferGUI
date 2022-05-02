#include "mySnifferGUI.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    mySnifferGUI w;
    w.show();
    return a.exec();
}
