// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/nix-config.h"
#endif

#include "ghostvault.h"
#include <qt/forms/ui_ghostvault.h>

#include "addresstablemodel.h"
#include "walletmodel.h"
#include "nixgui.h"
#include "csvmodelwriter.h"
#include "editaddressdialog.h"
#include "guiutil.h"
#include "platformstyle.h"
#include <wallet/wallet.h>
#include "qt/recentrequeststablemodel.h"
#include <ghost-address/commitmentkey.h>
#include <qt/coincontroldialog.h>

#include <QIcon>
#include <QMenu>
#include <QMessageBox>
#include <QSortFilterProxyModel>
#include <QTableWidgetItem>
#include <QAction>
#include <QDialog>
#include <QHeaderView>
#include <QItemSelection>
#include <QKeyEvent>
#include <QMenu>
#include <QPoint>
#include <QVariant>

GhostVault::GhostVault(const PlatformStyle *platformStyle, Mode mode, QWidget *parent) :
        QWidget(parent),
        ui(new Ui::GhostVault),
        model(0),
        mode(mode){
    ui->setupUi(this);

    switch (mode) {
        case ForSelection:
            setWindowTitle(tr("Ghost Vault"));
            break;
        case ForEditing:
            setWindowTitle(tr("Ghost Vault"));
    }

    ui->ghostAmount->setValidator( new QIntValidator(1, 9999999, this) );
    ui->labelExplanation->setTextFormat(Qt::RichText);
    ui->labelExplanation->setText(
            tr("<b>WARNING:</b> The Ghostvault is an experimental add-on, use with caution.<br><br>These are your private coins from ghosting NIX. You can convert ghosted NIX to public coins. The longer your coins are here, the more private they become."));
    ui->ghostAmount->setVisible(true);
    ui->ghostNIXButton->setVisible(true);
    ui->convertGhostButton->setVisible(true);

    ui->convertNIXAmount->clear();

    ui->unconfirmed_label->setText(QString::number(vpwallets.front()->GetGhostBalanceUnconfirmed()/COIN) + tr(" Unconfirmed NIX"));
    ui->total->setText(QString::number(vpwallets.front()->GetGhostBalance()/COIN) + tr(" Ghosted NIX"));

    // Build context menu
    contextMenu = new QMenu(this);

    QAction *copyKeyAction = new QAction(tr("Copy Key"), this);
    contextMenu = new QMenu(this);
    contextMenu->addAction(copyKeyAction);

    connect(copyKeyAction, SIGNAL(triggered()), this, SLOT(copyKey()));

    connect(ui->convertGhostToMeCheckBox, SIGNAL(stateChanged(int)), this, SLOT(convertGhostToMeCheckBoxChecked(int)));
    connect(ui->ghostToMeCheckBox, SIGNAL(stateChanged(int)), this, SLOT(ghostToMeCheckBoxChecked(int)));
    ui->keyPackAmount->addItem("1");
    ui->keyPackAmount->addItem("2");
    ui->keyPackAmount->addItem("3");
    ui->keyPackAmount->addItem("4");
    ui->keyPackAmount->addItem("5");
    ui->keyPackAmount->addItem("6");
    ui->keyPackAmount->addItem("7");
    ui->keyPackAmount->addItem("8");
    ui->keyPackAmount->addItem("9");
    ui->keyPackAmount->addItem("10");
    //set to default pack size
    ui->keyPackAmount->setCurrentIndex(ui->keyPackAmount->findText("10"));
    connect(ui->keyPackAmount, SIGNAL(currentIndexChanged(int)), this, SLOT(setKeyListTrigger(int)));

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

    // Select row for newly created address
    connect(model, SIGNAL(rowsInserted(QModelIndex, int, int)), this, SLOT(selectNewAddress(QModelIndex, int, int)));

}

void GhostVault::setWalletModel(WalletModel *walletmodel) {

    if (!walletmodel)
        return;

    this->walletModel = walletmodel;

    if(walletmodel && walletmodel->getOptionsModel())
    {
        tableView = ui->keyPackList;

        tableView->verticalHeader()->show();
        //tableView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        tableView->setAlternatingRowColors(false);
        tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableView->setSelectionMode(QAbstractItemView::ContiguousSelection);
        tableView->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showMenu(QPoint)));

        vector <CommitmentKeyPack> keyPackList;
        if (!walletmodel->getKeyPackList(keyPackList, ui->keyPackAmount->currentIndex() + 1))
            return;
        //Initialize table with keypacks
        for (auto r=0; r<10; r++)
            tableView->setItem(r, 0, new QTableWidgetItem(QString::fromStdString(keyPackList[r].GetPubCoinPackDataBase58())));
    }
}

void GhostVault::on_ghostNIXButton_clicked() { 
    QString amount = ui->ghostAmount->text();
    QString address = ui->ghostTo->text();
    std::string denomAmount = amount.toStdString();
    std::string stringError;

    std::string thirdPartyAddress = address.toStdString();

    CommitmentKeyPack keyPack;
    vector<CScript> pubCoinScripts;
    pubCoinScripts.clear();

    if(amount.toInt() < 1)
        QMessageBox::critical(this, tr("Error"),
                                      tr("You must ghost more than 0 coins."),
                                      QMessageBox::Ok, QMessageBox::Ok);

    if(ui->ghostToMeCheckBox->isChecked() == false){
        keyPack = CommitmentKeyPack(thirdPartyAddress);
        if(!keyPack.IsValidPack()){
            QMessageBox::critical(this, tr("Error"),
                                  tr("Not a valid key pack or address!"),
                                  QMessageBox::Ok, QMessageBox::Ok);
            return;
        }
        pubCoinScripts = keyPack.GetPubCoinPackScript();
    }



    if(walletModel->getWallet()->IsLocked()){
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if(!ctx.isValid())
        {
            return;
        }

        if(!walletModel->getWallet()->GhostModeMintTrigger(denomAmount,pubCoinScripts)){

            QMessageBox::critical(this, tr("Error"),
                                  tr("You cannot ghost NIX at the moment. Please check the debug.log for errors."),
                                  QMessageBox::Ok, QMessageBox::Ok);

        }else{
            QMessageBox::information(this, tr("Success"),
                                          tr("You have successfully ghosted NIX from your wallet"),
                                          QMessageBox::Ok, QMessageBox::Ok);

            ui->total->setText(QString::number(vpwallets.front()->GetGhostBalance()/COIN) + tr(" Ghosted NIX"));
            ui->unconfirmed_label->setText(QString::number(vpwallets.front()->GetGhostBalanceUnconfirmed()/COIN) + tr(" Unconfirmed NIX"));

            ui->convertNIXAmount->clear();
            ui->ghostAmount->clear();
        }
    }
    else{
        if(!walletModel->getWallet()->GhostModeMintTrigger(denomAmount, pubCoinScripts)){

            QMessageBox::critical(this, tr("Error"),
                                  tr("You cannot ghost NIX at the moment. Please check the debug.log for errors."),
                                  QMessageBox::Ok, QMessageBox::Ok);

        }else{
            QMessageBox::information(this, tr("Success"),
                                          tr("You have successfully ghosted NIX from your wallet"),
                                          QMessageBox::Ok, QMessageBox::Ok);


            ui->total->setText(QString::number(vpwallets.front()->GetGhostBalance()/COIN) + tr(" Ghosted NIX"));
            ui->unconfirmed_label->setText(QString::number(vpwallets.front()->GetGhostBalanceUnconfirmed()/COIN) + tr(" Unconfirmed NIX"));

            ui->convertNIXAmount->clear();
            ui->ghostAmount->clear();
        }
    }
}

void GhostVault::on_convertGhostButton_clicked() {

    QString amount = ui->convertNIXAmount->text();
    QString address = ui->convertGhostToThirdPartyAddress->text();
    std::string denomAmount = amount.toStdString();
    std::string thirdPartyAddress = address.toStdString();
    std::string stringError;

    CBitcoinAddress nixAddress;
    CommitmentKeyPack keyPack;

    // Address
    nixAddress = CBitcoinAddress(thirdPartyAddress);
    vector<CScript> pubCoinScripts = vector<CScript>();
    pubCoinScripts.clear();

    if(ui->convertGhostToMeCheckBox->isChecked() == false && !nixAddress.IsValid()){
        keyPack = CommitmentKeyPack(thirdPartyAddress);
        if(!keyPack.IsValidPack()){
            QMessageBox::critical(this, tr("Error"),
                                  tr("Not a valid key pack or address!"),
                                  QMessageBox::Ok, QMessageBox::Ok);
            return;
        }
        pubCoinScripts = keyPack.GetPubCoinPackScript();
    }


    if(ui->convertGhostToMeCheckBox->isChecked() == false && thirdPartyAddress == ""){
        QMessageBox::critical(this, tr("Error"),
                                      tr("Your \"Spend To\" field is empty, please check again"),
                                      QMessageBox::Ok, QMessageBox::Ok);
        return;
    }else{

        if(amount.toInt() < 1){
            QMessageBox::critical(this, tr("Error"),
                                          tr("You must ghost more than 0 coins."),
                                          QMessageBox::Ok, QMessageBox::Ok);
            return;
        }

        std::string successfulString = "Sucessfully sent " + denomAmount + " ghosted NIX";

        if(walletModel->getWallet()->IsLocked()){
            WalletModel::UnlockContext ctx(walletModel->requestUnlock());
            if(!ctx.isValid())
            {
                return;
            }

            stringError = walletModel->getWallet()->GhostModeSpendTrigger(denomAmount, thirdPartyAddress, pubCoinScripts);

        } else{
            stringError = walletModel->getWallet()->GhostModeSpendTrigger(denomAmount, thirdPartyAddress, pubCoinScripts);
        }

        if(stringError != successfulString){
            QString t = tr(stringError.c_str());

            QMessageBox::critical(this, tr("Error"),
                                  tr("You cannot convert ghosted NIX at the moment. %1").arg(t),
                                  QMessageBox::Ok, QMessageBox::Ok);
        }else{
            QMessageBox::information(this, tr("Success"),
                                          tr("You have successfully converted your ghosted NIX from your wallet"),
                                          QMessageBox::Ok, QMessageBox::Ok);

            ui->unconfirmed_label->setText(QString::number(vpwallets.front()->GetGhostBalanceUnconfirmed()/COIN) + tr(" Unconfirmed NIX"));

            ui->total->setText(QString::number(vpwallets.front()->GetGhostBalance()/COIN) + tr(" Ghosted NIX"));
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

void GhostVault::ghostToMeCheckBoxChecked(int state) {
    if (state == Qt::Checked)
    {
        ui->ghostTo->clear();
        ui->ghostTo->setEnabled(false);
    }else{
        ui->ghostTo->setEnabled(true);
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

}

void GhostVault::selectNewAddress(const QModelIndex &parent, int begin, int /*end*/) {
    QModelIndex idx = proxyModel->mapFromSource(model->index(begin, AddressTableModel::Address, parent));
    if (idx.isValid() && (idx.data(Qt::EditRole).toString() == newAddressToSelect)) {
        // Select row of newly created address, once
        newAddressToSelect.clear();
    }
}

void GhostVault::setVaultBalance(CAmount confirmed, CAmount unconfirmed){
    ui->total->setText(QString::number(confirmed/COIN) + tr(" Ghosted NIX"));
    ui->unconfirmed_label->setText(QString::number(unconfirmed/COIN) + tr(" Unconfirmed NIX"));
}

void GhostVault::setKeyList(){
    if(!walletModel || !tableView)
        return;
    vector <CommitmentKeyPack> keyPackList;
    if (!this->walletModel->getKeyPackList(keyPackList, ui->keyPackAmount->currentIndex() + 1))
        return;
    //Initialize table with keypacks
    for (auto r=0; r<10; r++)
        tableView->setItem(r, 0, new QTableWidgetItem(QString::fromStdString(keyPackList[r].GetPubCoinPackDataBase58())));
}

QModelIndex GhostVault::selectedRow()
{
    QModelIndexList selection = ui->keyPackList->selectionModel()->selectedRows();
    if(selection.empty())
        return QModelIndex();
    // correct for selection mode ContiguousSelection
    QModelIndex firstIndex = selection.at(0);
    return firstIndex;
}
// context menu
void GhostVault::showMenu(const QPoint &point)
{
    if (!selectedRow().isValid()) {
        return;
    }
    contextMenu->exec(QCursor::pos());
}

// context menu action: copy URI
void GhostVault::copyKey()
{
    QModelIndex sel = selectedRow();
    if (!sel.isValid()) {
        return;
    }
    GUIUtil::setClipboard(ui->keyPackList->item(sel.row(),0)->text());
}

void GhostVault::setKeyListTrigger(int state){
    setKeyList();
}
