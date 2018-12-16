// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/nix-config.h"
#endif

#include <qt/delegatedstaking.h>
#include <qt/forms/ui_delegatedstaking.h>


#include <qt/sendcoinsdialog.h>
#include <qt/addresstablemodel.h>
#include <qt/nixgui.h>
#include <qt/csvmodelwriter.h>
#include <qt/editaddressdialog.h>
#include <net.h>

#include <script/script.h>
#include <qt/nixunits.h>
#include <qt/clientmodel.h>
#include <qt/coincontroldialog.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>
#include <wallet/wallet.h>
#include <wallet/coincontrol.h>
#include <script/ismine.h>
#include <qt/recentrequeststablemodel.h>
#include <ghost-address/commitmentkey.h>

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
#include <QString>

DelegatedStaking::DelegatedStaking(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::DelegatedStaking),
    model(0),
    platformStyle(platformStyle)
{

    ui->setupUi(this);

    setWindowTitle(tr("Leased Staking"));

    QDoubleValidator *doubleValidator= new QDoubleValidator(this);
    doubleValidator->setBottom(0.00);
    doubleValidator->setDecimals(2);
    doubleValidator->setTop(100.00);
    doubleValidator->setNotation(QDoubleValidator::StandardNotation);

    ui->feePercent->setValidator(doubleValidator);

    ui->feePercent->setEnabled(false);
    ui->rewardTo->setEnabled(false);
    ui->enableFeePayout->setVisible(true);

    ui->activeContractsView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->activeContractsView->setAlternatingRowColors(true);
    ui->activeContractsView->setContextMenuPolicy(Qt::CustomContextMenu);


    contextMenu = new QMenu(this);
    contextMenu->setObjectName("contextMenu");


    QAction *cancelContractAction = new QAction(tr("Cancel contract"), this);
    contextMenu->addAction(cancelContractAction);

    connect(ui->sendButton, SIGNAL(triggered()), this, SLOT(on_sendButton_clicked()));

    connect(ui->enableFeePayout, SIGNAL(stateChanged(int)), this, SLOT(enableFeePayoutCheckBoxChecked(int)));

    connect(cancelContractAction, SIGNAL(triggered()), this, SLOT(cancelContract()));

    connect(ui->activeContractsView, SIGNAL(customContextMenuRequested(const QPoint&)), this, SLOT(showContextMenu(const QPoint&)));

}

DelegatedStaking::~DelegatedStaking() {
    delete ui;
}

void DelegatedStaking::setWalletModel(WalletModel *walletmodel) {
    if (!walletmodel)
        return;

    this->walletModel = walletmodel;
    updateContractList();
}

void DelegatedStaking::enableFeePayoutCheckBoxChecked(int state){
    if (state == Qt::Checked)
    {
        ui->feePercent->clear();
        ui->rewardTo->clear();
        ui->feePercent->setEnabled(true);
        ui->rewardTo->setEnabled(true);
    }else{
        ui->feePercent->clear();
        ui->rewardTo->clear();
        ui->feePercent->setEnabled(false);
        ui->rewardTo->setEnabled(false);
    }
}

void DelegatedStaking::processDelegatedCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg)
{
    QPair<QString, CClientUIInterface::MessageBoxFlags> msgParams;
    // Default to a warning message, override if error message is needed
    msgParams.second = CClientUIInterface::MSG_WARNING;

    // This comment is specific to SendCoinsDialog usage of WalletModel::SendCoinsReturn.
    // WalletModel::TransactionCommitFailed is used only in WalletModel::sendCoins()
    // all others are used only in WalletModel::prepareTransaction()
    switch(sendCoinsReturn.status)
    {
    case WalletModel::InvalidAddress:
        msgParams.first = tr("The recipient address is not valid. Please recheck.");
        break;
    case WalletModel::InvalidAmount:
        msgParams.first = tr("The amount to pay must be larger than 0.");
        break;
    case WalletModel::AmountExceedsBalance:
        msgParams.first = tr("The amount exceeds your balance.");
        break;
    case WalletModel::AmountWithFeeExceedsBalance:
        msgParams.first = tr("The total exceeds your balance when the %1 transaction fee is included.").arg(msgArg);
        break;
    case WalletModel::DuplicateAddress:
        msgParams.first = tr("Duplicate address found: addresses should only be used once each.");
        break;
    case WalletModel::TransactionCreationFailed:
        msgParams.first = tr("Transaction creation failed!");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    case WalletModel::TransactionCommitFailed:
        msgParams.first = tr("The transaction was rejected with the following reason: %1").arg(sendCoinsReturn.reasonCommitFailed);
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    case WalletModel::AbsurdFee:
        msgParams.first = tr("A fee higher than %1 is considered an absurdly high fee.").arg(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), maxTxFee));
        break;
    case WalletModel::PaymentRequestExpired:
        msgParams.first = tr("Payment request expired.");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    // included to prevent a compiler warning.
    case WalletModel::OK:
    default:
        return;
    }

    Q_EMIT message(tr("Lease Coins"), msgParams.first, msgParams.second);
}

void DelegatedStaking::on_sendButton_clicked()
{
    if(!walletModel)
        return;

    if(chainActive.Height() < Params().GetConsensus().nStartGhostFeeDistribution)
        Q_EMIT message(tr("Lease Coins"), tr("You must wait until block 115,921 to create LPoS contracts!"), CClientUIInterface::MSG_ERROR);

    if(IsInitialBlockDownload())
        Q_EMIT message(tr("Lease Coins"), tr("You must wait until you are fully synced create LPoS contracts!"), CClientUIInterface::MSG_ERROR);

    QList<SendCoinsRecipient> recipients;

    SendCoinsRecipient dposRecipient;

    // Normal payment
    dposRecipient.address = ui->delegateTo->text();
    dposRecipient.amount = ui->payAmount->value();
    dposRecipient.fSubtractFeeFromAmount = (ui->checkboxSubtractFeeFromAmount->checkState() == Qt::Checked);

    recipients.append(dposRecipient);

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if(!ctx.isValid())
    {
        // Unlock wallet was cancelled
        return;
    }

    // prepare transaction for getting txFee earlier
    WalletModelTransaction currentTransaction(recipients);
    WalletModel::SendCoinsReturn prepareStatus;

    // Always use a CCoinControl instance, use the CoinControlDialog instance if CoinControl has been enabled
    CCoinControl ctrl;
    if (walletModel->getOptionsModel()->getCoinControlFeatures())
        ctrl = *CoinControlDialog::coinControl();

    prepareStatus = walletModel->prepareTransaction(currentTransaction, ctrl);

    // process prepareStatus and on error generate message shown to user
    processDelegatedCoinsReturn(prepareStatus,
        BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), currentTransaction.getTransactionFee()));

    if(prepareStatus.status != WalletModel::OK) {
        return;
    }

    CAmount txFee = currentTransaction.getTransactionFee();

    // Format confirmation message
    QStringList formatted;
    for (const SendCoinsRecipient &rcp : currentTransaction.getRecipients())
    {
        // generate bold amount string
        QString amount = "<b>" + BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), rcp.amount);
        amount.append("</b>");
        // generate monospace address string
        QString address = "<span style='font-family: monospace;'>" + rcp.address;
        address.append("</span>");

        QString recipientElement;

        if (!rcp.paymentRequest.IsInitialized()) // normal payment
        {
            if(rcp.label.length() > 0) // label with address
            {
                recipientElement = tr("%1 leased to %2").arg(amount, GUIUtil::HtmlEscape(rcp.label));
                recipientElement.append(QString(" (%1)").arg(address));
            }
            else // just address
            {
                recipientElement = tr("%1 leased to %2").arg(amount, address);
            }
        }
        else if(!rcp.authenticatedMerchant.isEmpty()) // authenticated payment request
        {
            recipientElement = tr("%1 to %2").arg(amount, GUIUtil::HtmlEscape(rcp.authenticatedMerchant));
        }
        else // unauthenticated payment request
        {
            recipientElement = tr("%1 to %2").arg(amount, address);
        }

        formatted.append(recipientElement);
    }

    QString questionString = tr("Are you sure you want to send?");
    questionString.append("<br /><br />%1");

    if(txFee > 0)
    {
        // append fee string if a fee is required
        questionString.append("<hr /><span style='color:#aa0000;'>");
        questionString.append(BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), txFee));
        questionString.append("</span> ");
        questionString.append(tr("added as transaction fee"));

        // append transaction size
        questionString.append(" (" + QString::number((double)currentTransaction.getTransactionSize() / 1000) + " kB)");
    }

    // add total amount in all subdivision units
    questionString.append("<hr />");
    CAmount totalAmount = currentTransaction.getTotalTransactionAmount() + txFee;
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

    if (!walletModel->getWallet()->IsLocked()) {
        walletModel->getWallet()->TopUpKeyPool();
    }

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!walletModel->getWallet()->GetKeyFromPool(newKey)) {
        return;
    }

    walletModel->getWallet()->LearnRelatedScripts(newKey, g_address_type);
    CTxDestination dest = GetDestinationForKey(newKey, g_address_type);

    walletModel->getWallet()->SetAddressBook(dest, ui->contractLabel->text().toStdString(), "receive");

    CScript  delegateScript = GetScriptForDestination(CBitcoinAddress(ui->delegateTo->text().toStdString()).Get());

    CScript scriptPubKeyKernel = GetScriptForDestination(dest);
    //set up contract
    CScript script = CScript() << OP_ISCOINSTAKE << OP_IF;
    //cold stake address
    script += delegateScript;
    script << OP_ELSE;
    //local wallet address
    script += scriptPubKeyKernel;
    script << OP_ENDIF;

    if(ui->enableFeePayout->isChecked() == true){

        int64_t nFeePercent = (int64_t) (ui->feePercent->text().toDouble() * 100);
        if(nFeePercent > 10000 || nFeePercent < 0){
            Q_EMIT message(tr("Lease Coins"), tr("Lease fee percent is not valid"), CClientUIInterface::MSG_ERROR);
            return;
        }
        script << nFeePercent;
        script << OP_DROP;

        CBitcoinAddress delegateReward(ui->rewardTo->text().toStdString());
        if(!delegateReward.IsValid() || !delegateReward.IsScript()){
            Q_EMIT message(tr("Lease Coins"), tr("Lease reward address is not valid"), CClientUIInterface::MSG_ERROR);
            return;
        }

        //Returns false if not coldstake or p2sh script
        CScriptID destDelegateReward;
        if (!ExtractStakingKeyID(GetScriptForDestination(delegateReward.Get()), destDelegateReward)){
            Q_EMIT message(tr("Lease Coins"), tr("ExtractStakingKeyID is not valid"), CClientUIInterface::MSG_ERROR);
            return;
        }

        script << ToByteVector(destDelegateReward);
        script << OP_DROP;
    }

    scriptPubKeyKernel = script;

    SendConfirmationDialog confirmationDialog(tr("Confirm lease coins"),
        questionString.arg(formatted.join("<br />")), SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

    if(retval != QMessageBox::Yes)
    {
        return;
    }

    // Create and send the transaction
    CReserveKey reservekey(walletModel->getWallet());
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKeyKernel, ui->payAmount->value(), dposRecipient.fSubtractFeeFromAmount};
    vecSend.push_back(recipient);

    CWalletTx wtx;

    if (!walletModel->getWallet()->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError, ctrl)) {
        Q_EMIT message(tr("Lease Coins"), tr(strError.c_str()), CClientUIInterface::MSG_ERROR);
        return;
    }
    CValidationState state;
    if (!walletModel->getWallet()->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
        Q_EMIT message(tr("Lease Coins"), tr(strError.c_str()), CClientUIInterface::MSG_ERROR);
        return;
    }


    //accept();
    CoinControlDialog::coinControl()->UnSelectAll();
    updateContractList();
    //coinControlUpdateLabels();
}


void DelegatedStaking::updateContractList() {

    if (!walletModel)
        return;

    ui->activeContractsView->setRowCount(0);
    activeContractsOutpoints.clear();
    activeContractsAmounts.clear();
    std::map<QString, std::vector<COutput> > mapCoins;
    walletModel->listCoins(mapCoins);

    for (const std::pair<QString, std::vector<COutput>>& coins : mapCoins) {
        CAmount nSum = 0;
        for (const COutput& out : coins.second) {
            nSum = out.tx->tx->vout[out.i].nValue;

            // address
            CTxDestination ownerDest;
            if(out.tx->tx->vout[out.i].scriptPubKey.IsPayToScriptHash_CS()){
                if(ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, ownerDest))
                {
                    CScript delegateScript;
                    int64_t feeAmount;
                    CScript feeRewardScript;
                    CScriptID hash = boost::get<CScriptID>(ownerDest);

                    if(walletModel->getWallet()->HaveCScript(hash)){
                        GetCoinstakeScriptPath(out.tx->tx->vout[out.i].scriptPubKey, delegateScript);
                        bool hasFee = GetCoinstakeScriptFee(out.tx->tx->vout[out.i].scriptPubKey, feeAmount);
                        GetCoinstakeScriptFeeRewardAddress(out.tx->tx->vout[out.i].scriptPubKey, feeRewardScript);

                        CBitcoinAddress addr1(ownerDest);

                        CTxDestination delegateDest;
                        ExtractDestination(delegateScript, delegateDest);
                        CBitcoinAddress addr2(delegateDest);

                        CTxDestination rewardFeeDest;
                        ExtractDestination(feeRewardScript, rewardFeeDest);
                        CBitcoinAddress addr3(rewardFeeDest);

                        if(!hasFee)
                            feeAmount = 0;

                        std::string ownerAddrString = addr1.ToString();
                        if(walletModel->getWallet()->mapAddressBook.find(ownerDest) != walletModel->getWallet()->mapAddressBook.end())
                        {
                            ownerAddrString = walletModel->getWallet()->mapAddressBook[ownerDest].name;
                        }

                        QTableWidgetItem *myAddress = new QTableWidgetItem(QString::fromStdString(ownerAddrString));
                        QTableWidgetItem *delegateAddress = new QTableWidgetItem(QString::fromStdString(addr2.ToString()));
                        QTableWidgetItem *contractFee = new QTableWidgetItem(QString::fromStdString(std::to_string((double)feeAmount/100.00)));
                        QTableWidgetItem *rewardFeeAddress = new QTableWidgetItem(QString::fromStdString(addr3.ToString()));
                        QTableWidgetItem *coinAmount = new QTableWidgetItem(BitcoinUnits::format(walletModel->getOptionsModel()->getDisplayUnit(), nSum));

                        if(!hasFee)
                             rewardFeeAddress = new QTableWidgetItem(QString::fromStdString("N/A"));

                        ui->activeContractsView->insertRow(0);
                        ui->activeContractsView->setItem(0, 0, myAddress);
                        ui->activeContractsView->setItem(0, 1, delegateAddress);
                        ui->activeContractsView->setItem(0, 2, contractFee);
                        ui->activeContractsView->setItem(0, 3, rewardFeeAddress);
                        ui->activeContractsView->setItem(0, 4, coinAmount);

                        //Lock contracts
                        COutPoint outpt(out.tx->tx->GetHash(), out.i);
                        walletModel->lockCoin(outpt);

                        activeContractsOutpoints.push_back(outpt);
                        activeContractsAmounts.push_back(nSum);
                    }

                }
            }

        }
    }
}

void DelegatedStaking::showContextMenu(const QPoint &point)
{
    QTableWidgetItem *item = ui->activeContractsView->itemAt(point);
    if(item) contextMenu->exec(QCursor::pos());
}

void DelegatedStaking::cancelContract(){

    if(!ui->activeContractsView || !ui->activeContractsView->selectionModel())
        return;

    QModelIndexList selection = ui->activeContractsView->selectionModel()->selectedRows(0);

    if(!selection.isEmpty())
    {
        // Select proper transaction inputs to coincontrol
        CCoinControl ctrl;
        ctrl = *CoinControlDialog::coinControl();
        ctrl.UnSelectAll();
        int row = -1;
        for(QModelIndex rowIndex: selection) {
            row = rowIndex.row();
            //unlock contract
            walletModel->unlockCoin(activeContractsOutpoints[activeContractsOutpoints.size() - 1 - row]);
            ctrl.Select(activeContractsOutpoints[activeContractsOutpoints.size() - 1 - row]);
        }
        CAmount totalAmount = activeContractsAmounts[activeContractsAmounts.size() - 1 - row];

        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if(!ctx.isValid())
        {
            // Unlock wallet was cancelled
            return;
        }

        if (!walletModel->getWallet()->IsLocked()) {
            walletModel->getWallet()->TopUpKeyPool();
        }

        // Generate a new key that is added to wallet
        CPubKey newKey;
        if (!walletModel->getWallet()->GetKeyFromPool(newKey)) {
            return;
        }

        walletModel->getWallet()->LearnRelatedScripts(newKey, g_address_type);
        CTxDestination dest = GetDestinationForKey(newKey, g_address_type);

        //if(ui->contractLabel->text().toStdString() != "")
            //walletModel->getWallet()->SetAddressBook(dest, ui->contractLabel->text().toStdString(), "receive");

        CScript scriptPubKey = GetScriptForDestination(dest);


        // Create and send the transaction
        CReserveKey reservekey(walletModel->getWallet());
        CAmount nFeeRequired;
        std::string strError;
        std::vector<CRecipient> vecSend;
        int nChangePosRet = -1;
        CRecipient recipient = {scriptPubKey, totalAmount, true};
        vecSend.push_back(recipient);

        CWalletTx wtx;

        if (!walletModel->getWallet()->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError, ctrl)) {
            Q_EMIT message(tr("Cancel Contract"), tr(strError.c_str()), CClientUIInterface::MSG_ERROR);
            return;
        }

        /**************************************************************************************************************
         **************************************************************************************************************
         **************************************************************************************************************
         *  Format send dialog  */

        // Format confirmation message
        QStringList formatted;

        // generate bold amount string
        QString amount = "<b>" + BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), totalAmount);
        amount.append("</b>");

        QString recipientElement;

        recipientElement = tr("contract of %1 cancelled").arg(amount);


        formatted.append(recipientElement);


        QString questionString = tr("Are you sure you want to cancel this contract?");
        questionString.append("<br /><br />%1");

        if(nFeeRequired > 0)
        {
            // append fee string if a fee is required
            questionString.append("<hr /><span style='color:#aa0000;'>");
            questionString.append(BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), nFeeRequired));
            questionString.append("</span> ");
            questionString.append(tr("subtracted as transaction fee"));

            // append transaction size
            questionString.append(" (" + QString::number((double)GetTransactionWeight(*wtx.tx) / 1000) + " kB)");
        }

        // add total amount in all subdivision units
        questionString.append("<hr />");
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

        SendConfirmationDialog confirmationDialog(tr("Confirm cancel contract"),
            questionString.arg(formatted.join("<br />")), SEND_CONFIRM_DELAY, this);
        confirmationDialog.exec();
        QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

        if(retval != QMessageBox::Yes)
        {
            return;
        }

        /**************************************************************************************************************
         **************************************************************************************************************
         **************************************************************************************************************
         *  End send dialog  */

        CValidationState state;
        if (!walletModel->getWallet()->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
            Q_EMIT message(tr("Cancel Contract"), tr(strError.c_str()), CClientUIInterface::MSG_ERROR);
            return;
        }

        CoinControlDialog::coinControl()->UnSelectAll();
        updateContractList();
    }
}
