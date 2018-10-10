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

    connect(ui->convertGhostToMeCheckBox, SIGNAL(stateChanged(int)), this, SLOT(convertGhostToMeCheckBoxChecked(int)));
    connect(ui->ghostToMeCheckBox, SIGNAL(stateChanged(int)), this, SLOT(ghostToMeCheckBoxChecked(int)));

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

    QTableView* tableView = ui->keyPackList;

    tableView->verticalHeader()->hide();
    tableView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    tableView->setAlternatingRowColors(true);
    tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableView->setSelectionMode(QAbstractItemView::ContiguousSelection);
    tableView->setColumnWidth(0, 120);
    tableView->setColumnWidth(1, 180);

    connect(tableView->selectionModel(),
        SIGNAL(selectionChanged(QItemSelection, QItemSelection)), this,
        SLOT(recentRequestsView_selectionChanged(QItemSelection, QItemSelection)));
}

void GhostVault::on_ghostNIXButton_clicked() {
    QString amount = ui->ghostAmount->text();
    std::string denomAmount = amount.toStdString();
    std::string stringError;

    if(amount.toInt() < 1)
        QMessageBox::critical(this, tr("Error"),
                                      tr("You must ghost more than 0 coins."),
                                      QMessageBox::Ok, QMessageBox::Ok);

    if(walletModel->getWallet()->IsLocked()){
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if(!ctx.isValid())
        {
            return;
        }
        if(!walletModel->getWallet()->GhostModeMintTrigger(denomAmount)){

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
        if(!walletModel->getWallet()->GhostModeMintTrigger(denomAmount)){

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

    if(!nixAddress.IsValid()){
        keyPack = CommitmentKeyPack(thirdPartyAddress);
        if(!keyPack.IsValidPack()){
            QMessageBox::critical(this, tr("Error"),
                                  tr("Not a valid key pack or address!"),
                                  QMessageBox::Ok, QMessageBox::Ok);
            return;
        }
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

        vector<CScript> pubCoinScripts = vector<CScript>();

        if(!nixAddress.IsValid())
            pubCoinScripts = keyPack.GetPubCoinPackScript();

        if(walletModel->getWallet()->IsLocked()){
            WalletModel::UnlockContext ctx(walletModel->requestUnlock());
            if(!ctx.isValid())
            {
                return;
            }

            if(nixAddress.IsValid())
                stringError = walletModel->getWallet()->GhostModeSpendTrigger(denomAmount, thirdPartyAddress);
            else
                stringError = walletModel->getWallet()->GhostModeSpendTrigger(denomAmount, "", pubCoinScripts);

        } else{
            if(nixAddress.IsValid())
                stringError = walletModel->getWallet()->GhostModeSpendTrigger(denomAmount, thirdPartyAddress);
            else
                stringError = walletModel->getWallet()->GhostModeSpendTrigger(denomAmount, "", pubCoinScripts);
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
