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
#include <wallet/coincontrol.h>
#include "qt/recentrequeststablemodel.h"
#include <ghost-address/commitmentkey.h>
#include <qt/coincontroldialog.h>
#include <qt/nixunits.h>
#include <qt/optionsmodel.h>
#include <qt/receiverequestdialog.h>
#include <qt/sendcoinsdialog.h>

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

    ui->ghostAmount->setValidator(new QDoubleValidator(0.1, 9999999.0, 1, this));
    ui->convertNIXAmount->setValidator(new QDoubleValidator(0.1, 9999999.0, 1, this) );
    ui->labelExplanation->setTextFormat(Qt::RichText);
    ui->labelExplanation->setText(
            tr("These are your private coins from ghosting NIX. You can convert ghosted NIX to public coins. The longer your coins are here, the more private they become. "
               "(<b>TIP</b>: This page works with coin-control)"));
    ui->ghostAmount->setVisible(true);
    ui->ghostNIXButton->setVisible(true);
    ui->convertGhostButton->setVisible(true);

    ui->convertNIXAmount->clear();

    int unit = BitcoinUnits::BTC;
    CAmount balance = vpwallets.front()->GetGhostBalance(true);
    ui->total->setText(BitcoinUnits::formatWithUnit(unit, balance, false, BitcoinUnits::separatorAlways) + tr(" Ghosted NIX"));

    CAmount unconfirmedBalance = vpwallets.front()->GetGhostBalanceUnconfirmed(true);
    ui->unconfirmed_label->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedBalance, false, BitcoinUnits::separatorAlways) + tr(" Unconfirmed NIX"));

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
    //connect(ui->keyPackAmount, SIGNAL(currentIndexChanged(int)), this, SLOT(setKeyListTrigger(int)));

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

    if(amount.toDouble() < 0.1)
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
        for(auto scriptK: pubCoinScripts){
            LogPrintf("\npubcoin script = %s\n", HexStr(scriptK.begin(), scriptK.end()));
            secp_primitives::GroupElement pubCoinValue = ParseSigmaMintScript(scriptK);
            sigma::PublicCoin pubCoin(pubCoinValue, sigma::CoinDenomination::SIGMA_0_1);
            if(!pubCoin.validate()){
                QMessageBox::critical(this, tr("Error"),
                                      tr("Cannot validate pubcoin!"),
                                      QMessageBox::Ok, QMessageBox::Ok);
                return;
            }
        }
    }

    QString questionString = tr("Are you sure you want to ghost coins?");

    CAmount txFee = 0;
    CAmount totalAmount;
    if (!ParseFixedPoint(denomAmount, 8, &totalAmount))
        return;
    if (!MoneyRange(totalAmount))
        return;

    txFee = totalAmount * 0.0025;

    if(txFee > 0)
    {
        // append fee string if a fee is required
        questionString.append("<hr /><span style='color:#aa0000;'>");
        questionString.append(BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), txFee));
        questionString.append("</span> ");
        questionString.append(tr("added as transaction fee (0.25%)"));
    }

    // add total amount in all subdivision units
    questionString.append("<hr />");
    totalAmount = totalAmount + txFee;
    QStringList alternativeUnits;
    for (BitcoinUnits::Unit u : BitcoinUnits::availableUnits())
    {
        if(u != walletModel->getOptionsModel()->getDisplayUnit())
            alternativeUnits.append(BitcoinUnits::formatHtmlWithUnit(u, totalAmount));
    }
    questionString.append(tr("Total Amount %1")
        .arg(BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), totalAmount)));
    questionString.append(QString("<span style='font-size:10pt;font-weight:normal;'><br />(=%1)</span>")
        .arg(alternativeUnits.join(" " + tr("or") + "<br />")));

    questionString.append("<hr /><span>");
    questionString.append("</span>");


    if (walletModel->getOptionsModel()->getCoinControlFeatures())
        g_coincontrol = *CoinControlDialog::coinControl();

    if(walletModel->getWallet()->IsLocked()){
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if(!ctx.isValid())
        {
            return;
        }

        SendConfirmationDialog confirmationDialog(tr("Confirm lease coins"),
            questionString, SEND_CONFIRM_DELAY, this);
        confirmationDialog.exec();
        QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

        if(retval != QMessageBox::Yes)
        {
            return;
        }

        if(!walletModel->getWallet()->GhostModeMintSigma(denomAmount,pubCoinScripts)){

            QMessageBox::critical(this, tr("Error"),
                                  tr("You cannot ghost NIX at the moment. Please check the debug.log for errors."),
                                  QMessageBox::Ok, QMessageBox::Ok);

        }else{
            QMessageBox::information(this, tr("Success"),
                                          tr("You have successfully ghosted NIX from your wallet"),
                                          QMessageBox::Ok, QMessageBox::Ok);

            int unit = walletModel->getOptionsModel()->getDisplayUnit();
            CAmount balance = vpwallets.front()->GetGhostBalance(true);
            ui->total->setText(BitcoinUnits::formatWithUnit(unit, balance, false, BitcoinUnits::separatorAlways) + tr(" Ghosted NIX"));

            CAmount unconfirmedBalance = vpwallets.front()->GetGhostBalanceUnconfirmed(true);
            ui->unconfirmed_label->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedBalance, false, BitcoinUnits::separatorAlways) + tr(" Unconfirmed NIX"));


            ui->convertNIXAmount->clear();
            ui->ghostAmount->clear();
        }
    }
    else{

        SendConfirmationDialog confirmationDialog(tr("Confirm lease coins"),
            questionString, SEND_CONFIRM_DELAY, this);
        confirmationDialog.exec();
        QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

        if(retval != QMessageBox::Yes)
        {
            return;
        }

        if(!walletModel->getWallet()->GhostModeMintSigma(denomAmount, pubCoinScripts)){

            QMessageBox::critical(this, tr("Error"),
                                  tr("You cannot ghost NIX at the moment. Please check the debug.log for errors."),
                                  QMessageBox::Ok, QMessageBox::Ok);

        }else{
            QMessageBox::information(this, tr("Success"),
                                          tr("You have successfully ghosted NIX from your wallet"),
                                          QMessageBox::Ok, QMessageBox::Ok);

            int unit = walletModel->getOptionsModel()->getDisplayUnit();
            CAmount balance = vpwallets.front()->GetGhostBalance(true);
            ui->total->setText(BitcoinUnits::formatWithUnit(unit, balance, false, BitcoinUnits::separatorAlways) + tr(" Ghosted NIX"));

            CAmount unconfirmedBalance = vpwallets.front()->GetGhostBalanceUnconfirmed(true);
            ui->unconfirmed_label->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedBalance, false, BitcoinUnits::separatorAlways) + tr(" Unconfirmed NIX"));

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

    CTxDestination nixAddr;
    CommitmentKeyPack keyPack;

    // Address
    nixAddr = DecodeDestination(thirdPartyAddress);
    vector<CScript> pubCoinScripts = vector<CScript>();
    pubCoinScripts.clear();

    if(ui->convertGhostToMeCheckBox->isChecked() == false && !IsValidDestination(nixAddr)){
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

        if(amount.toDouble() < 0.1){
            QMessageBox::critical(this, tr("Error"),
                                          tr("You must unghost more than 0 coins."),
                                          QMessageBox::Ok, QMessageBox::Ok);
            return;
        }

        std::string successfulString = "Sucessfully sent " + denomAmount + " ghosted NIX";

        QString questionString = tr("Are you sure you want to unghost coins?");

        CAmount txFee = 0;
        CAmount totalAmount;
        if (!ParseFixedPoint(denomAmount, 8, &totalAmount))
            return;
        if (!MoneyRange(totalAmount))
            return;

        if(!pubCoinScripts.empty())
            txFee = COIN/10;

        if(txFee > 0)
        {
            // append fee string if a fee is required
            questionString.append("<hr /><span style='color:#aa0000;'>");
            questionString.append(BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), txFee));
            questionString.append("</span> ");
            questionString.append(tr("added as transaction fee for 2-way ghosting payment"));
        }

        // add total amount in all subdivision units
        questionString.append("<hr />");
        totalAmount = totalAmount + txFee;
        QStringList alternativeUnits;
        for (BitcoinUnits::Unit u : BitcoinUnits::availableUnits())
        {
            if(u != walletModel->getOptionsModel()->getDisplayUnit())
                alternativeUnits.append(BitcoinUnits::formatHtmlWithUnit(u, totalAmount));
        }
        questionString.append(tr("Total Amount %1")
            .arg(BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), totalAmount)));
        questionString.append(QString("<span style='font-size:10pt;font-weight:normal;'><br />(=%1)</span>")
            .arg(alternativeUnits.join(" " + tr("or") + "<br />")));

        questionString.append("<hr /><span>");
        questionString.append("</span>");

        if (walletModel->getOptionsModel()->getCoinControlFeatures())
            g_coincontrol = *CoinControlDialog::coinControl();

        if(walletModel->getWallet()->IsLocked()){
            WalletModel::UnlockContext ctx(walletModel->requestUnlock());
            if(!ctx.isValid())
            {
                return;
            }

            SendConfirmationDialog confirmationDialog(tr("Confirm lease coins"),
                questionString, SEND_CONFIRM_DELAY, this);
            confirmationDialog.exec();
            QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

            if(retval != QMessageBox::Yes)
            {
                return;
            }

            stringError = walletModel->getWallet()->GhostModeSpendSigma(denomAmount, thirdPartyAddress, pubCoinScripts);

        } else{

            SendConfirmationDialog confirmationDialog(tr("Confirm lease coins"),
                questionString, SEND_CONFIRM_DELAY, this);
            confirmationDialog.exec();
            QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

            if(retval != QMessageBox::Yes)
            {
                return;
            }

            stringError = walletModel->getWallet()->GhostModeSpendSigma(denomAmount, thirdPartyAddress, pubCoinScripts);
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


            int unit = walletModel->getOptionsModel()->getDisplayUnit();
            CAmount balance = vpwallets.front()->GetGhostBalance(true);
            ui->total->setText(BitcoinUnits::formatWithUnit(unit, balance, false, BitcoinUnits::separatorAlways) + tr(" Ghosted NIX"));

            CAmount unconfirmedBalance = vpwallets.front()->GetGhostBalanceUnconfirmed(true);
            ui->unconfirmed_label->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedBalance, false, BitcoinUnits::separatorAlways) + tr(" Unconfirmed NIX"));
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
    int unit = walletModel->getOptionsModel()->getDisplayUnit();
    ui->total->setText(BitcoinUnits::formatWithUnit(unit, confirmed, false, BitcoinUnits::separatorAlways) + tr(" Ghosted NIX"));
    ui->unconfirmed_label->setText(BitcoinUnits::formatWithUnit(unit, unconfirmed, false, BitcoinUnits::separatorAlways) + tr(" Unconfirmed NIX"));
}

void GhostVault::setKeyList(){

}

QModelIndex GhostVault::selectedRow()
{
    /*
    QModelIndexList selection = ui->keyPackList->selectionModel()->selectedRows();
    if(selection.empty())
        return QModelIndex();
    // correct for selection mode ContiguousSelection
    QModelIndex firstIndex = selection.at(0);
    return firstIndex;
    */
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
    //GUIUtil::setClipboard(ui->keyPackList->item(sel.row(),0)->text());
}

void GhostVault::setKeyListTrigger(int state){
    setKeyList();
}

void GhostVault::on_generateGhostKey_clicked()
{
    if(!walletModel || !walletModel->getRecentRequestsTableModel())
        return;

    const RecentRequestsTableModel *submodel = walletModel->getRecentRequestsTableModel();
    ReceiveRequestDialog *dialog = new ReceiveRequestDialog(this);
    dialog->setModel(walletModel->getOptionsModel());
    SendCoinsRecipient printKey;
    printKey.authenticatedMerchant = "";

    /************************************/
    CWallet * const pwallet = walletModel->getWallet();

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!EnsureWalletIsAvailable(pwallet, false)) {
        return;
    }

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if(!ctx.isValid())
    {
        // Unlock wallet was cancelled
        return;
    }

    std::string keyPack;
    std::vector <CommitmentKeyPack> keyList;
    int keyAmount = ui->keyPackAmount->currentIndex() + 1;
    if(!walletModel->getKeyPackList(keyList, true, keyAmount))
        return;
    keyPack = keyList[0].GetPubCoinPackDataBase58();
    printKey.address = QString::fromStdString(keyPack);
    /************************************/

    //printKey.message = submodel->entry(index.row()).recipient.message;
    //printKey.amount = submodel->entry(index.row()).recipient.amount;
    printKey.label = tr("Ghost Key");
    dialog->setInfo(printKey);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->show();


}
