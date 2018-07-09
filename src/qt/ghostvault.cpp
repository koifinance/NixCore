// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/nix-config.h"
#endif

#include "ghostvault.h"
#include <qt/forms/ui_ghostvault.h>

#include "addresstablemodel.h"
#include "nixgui.h"
#include "csvmodelwriter.h"
#include "editaddressdialog.h"
#include "guiutil.h"
#include "platformstyle.h"
#include <wallet/wallet.h>

#include <QIcon>
#include <QMenu>
#include <QMessageBox>
#include <QSortFilterProxyModel>

GhostVault::GhostVault(const PlatformStyle *platformStyle, Mode mode, QWidget *parent) :
        QWidget(parent),
        ui(new Ui::GhostVault),
        model(0),
        mode(mode){
    ui->setupUi(this);

    if (!platformStyle->getImagesOnButtons()) {
        ui->exportButton->setIcon(QIcon());
    } else {
        ui->exportButton->setIcon(platformStyle->SingleColorIcon(":/icons/export"));
    }

    switch (mode) {
        case ForSelection:
            setWindowTitle(tr("Ghost Vault"));
            connect(ui->tableView, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(accept()));
            ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
            ui->tableView->setFocus();
            ui->exportButton->hide();
            break;
        case ForEditing:
            setWindowTitle(tr("Ghost Vault"));
    }
    ui->labelExplanation->setText(
            tr("These are your private coins from ghosting NIX, You can convert ghosted NIX to public coins."));
    ui->ghostAmount->setVisible(true);
    ui->ghostNIXButton->setVisible(true);
    ui->convertGhostButton->setVisible(true);
    ui->ghostAmount->addItem("1");
    ui->ghostAmount->addItem("5");
    ui->ghostAmount->addItem("10");
    ui->ghostAmount->addItem("50");
    ui->ghostAmount->addItem("100");
    ui->ghostAmount->addItem("500");
    ui->ghostAmount->addItem("1000");
    ui->ghostAmount->addItem("5000");

    ui->convertNIXAmount->clear();

    std::vector <COutput> vCoins;
    vpwallets.front()->ListAvailableCoinsMintCoins(vCoins, true);
    ui->total->setText(QString::number(vCoins.size()) + tr(" Ghosted NIX"));

    if(vCoins.size() == 0)
        ui->convertNIXAmount->addItem("None");
    else
        for(int i = 0; i < vCoins.size(); i++)
            ui->convertNIXAmount->addItem(QString::number(vCoins[i].tx->tx->vout[vCoins[i].i].nValue));
    // Build context menu
    contextMenu = new QMenu(this);

    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));
    connect(ui->convertGhostToMeCheckBox, SIGNAL(stateChanged(int)), this, SLOT(convertGhostToMeCheckBoxChecked(int)));

}

GhostVault::~GhostVault() {
    delete ui;
}

void GhostVault::setModel(AddressTableModel *model) {
    this->model = model;
    if (!model)
        return;

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterRole(AddressTableModel::TypeRole);
    proxyModel->setFilterFixedString(AddressTableModel::GhostVault);

    ui->tableView->setModel(proxyModel);
    ui->tableView->sortByColumn(0, Qt::AscendingOrder);

    // Set column widths
#if QT_VERSION < 0x050000
    ui->tableView->horizontalHeader()->setResizeMode(AddressTableModel::Label, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setResizeMode(AddressTableModel::Address, QHeaderView::ResizeToContents);
#else
    ui->tableView->horizontalHeader()->setSectionResizeMode(AddressTableModel::Label, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setSectionResizeMode(AddressTableModel::Address, QHeaderView::ResizeToContents);
#endif

    // Select row for newly created address
    connect(model, SIGNAL(rowsInserted(QModelIndex, int, int)), this, SLOT(selectNewAddress(QModelIndex, int, int)));

}

void GhostVault::on_ghostNIXButton_clicked() {
    QString amount = ui->ghostAmount->currentText();
    std::string denomAmount = amount.toStdString();
    std::string stringError;
    if(!model->ghostNIX(stringError, denomAmount)){
        QString t = tr(stringError.c_str());

        QMessageBox::critical(this, tr("Error"),
                              tr("You cannot ghost NIX because %1").arg(t),
                              QMessageBox::Ok, QMessageBox::Ok);
    }else{
        QMessageBox::information(this, tr("Success"),
                                      tr("You have been successfully ghosted NIX from your wallet"),
                                      QMessageBox::Ok, QMessageBox::Ok);
        std::vector <COutput> vCoins;
        (vpwallets.front())->ListAvailableCoinsMintCoins(vCoins, true);
        ui->total->setText(QString::number(vCoins.size()) + tr(" Ghosted NIX"));
        ui->convertNIXAmount->clear();
        if(vCoins.size() == 0)
            ui->convertNIXAmount->addItem("None");
        else
            for(int i = 0; i < vCoins.size(); i++)
                ui->convertNIXAmount->addItem(QString::number(vCoins[i].tx->tx->vout[vCoins[i].i].nValue));

    }
}

void GhostVault::on_convertGhostButton_clicked() {

    QString amount = ui->convertNIXAmount->currentText();
    QString address = ui->convertGhostToThirdPartyAddress->text();
    std::string denomAmount = amount.toStdString();
    std::string thirdPartyAddress = address.toStdString();
    std::string stringError;

    if(ui->convertGhostToMeCheckBox->isChecked() == false && thirdPartyAddress == ""){
        QMessageBox::critical(this, tr("Error"),
                                      tr("Your \"Spend To\" field is empty, please check again"),
                                      QMessageBox::Ok, QMessageBox::Ok);
    }else{

        if(!model->convertGhost(stringError, thirdPartyAddress, denomAmount)){
            QString t = tr(stringError.c_str());

            QMessageBox::critical(this, tr("Error"),
                                  tr("You cannot convert ghosted NIX because %1").arg(t),
                                  QMessageBox::Ok, QMessageBox::Ok);
        }else{
            QMessageBox::information(this, tr("Success"),
                                          tr("You have been successfully converted your ghosted NIX from the wallet"),
                                          QMessageBox::Ok, QMessageBox::Ok);

        }
        ui->convertGhostToThirdPartyAddress->clear();
        ui->convertGhostToThirdPartyAddress->setEnabled(false);

        ui->convertGhostToMeCheckBox->setChecked(true);
    }
}

void GhostVault::convertGhostToMeCheckBoxChecked(int state) {
    if (state == Qt::Checked)
    {
        ui->convertGhostToThirdPartyAddress->clear();
        ui->convertGhostToThirdPartyAddress->setEnabled(false);
    }else{
        ui->convertGhostToThirdPartyAddress->setEnabled(true);
    }
}


void GhostVault::on_exportButton_clicked() {
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(this, tr("Export Address List"), QString(), tr("Comma separated file (*.csv)"), NULL);

    if (filename.isNull())
        return;

    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(proxyModel);
    writer.addColumn("Label", AddressTableModel::Label, Qt::EditRole);
    writer.addColumn("Address", AddressTableModel::Address, Qt::EditRole);

    if (!writer.write()) {
        QMessageBox::critical(this, tr("Exporting Failed"), tr("There was an error trying to save the address list to %1. Please try again.").arg(
                filename));
    }
}

void GhostVault::contextualMenu(const QPoint &point) {
    QModelIndex index = ui->tableView->indexAt(point);
    if (index.isValid()) {
        contextMenu->exec(QCursor::pos());
    }
}

void GhostVault::selectNewAddress(const QModelIndex &parent, int begin, int /*end*/) {
    QModelIndex idx = proxyModel->mapFromSource(model->index(begin, AddressTableModel::Address, parent));
    if (idx.isValid() && (idx.data(Qt::EditRole).toString() == newAddressToSelect)) {
        // Select row of newly created address, once
        ui->tableView->setFocus();
        ui->tableView->selectRow(idx.row());
        newAddressToSelect.clear();
    }
}
