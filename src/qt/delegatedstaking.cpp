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

DelegatedStaking::DelegatedStaking(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::DelegatedStaking),
    model(0),
    platformStyle(platformStyle)
{

    ui->setupUi(this);

    setWindowTitle(tr("Delegated Staking"));

    QDoubleValidator *doubleValidator= new QDoubleValidator(this);
    doubleValidator->setBottom(0.00);
    doubleValidator->setDecimals(2);
    doubleValidator->setTop(100.00);
    doubleValidator->setNotation(QDoubleValidator::StandardNotation);

    ui->feePercent->setValidator(doubleValidator);

    ui->feePercent->setEnabled(false);
    ui->rewardTo->setEnabled(false);

    //ui->labelExplanation->setTextFormat(Qt::RichText);
    //ui->labelExplanation->setText(tr("Create DPoS smart contracts straight from your wallet. (Tip: This page works with coin-control)"));

    ui->enableFeePayout->setVisible(true);

    connect(ui->sendButton, SIGNAL(triggered()), this, SLOT(on_sendButton_clicked()));

    connect(ui->enableFeePayout, SIGNAL(stateChanged(int)), this, SLOT(enableFeePayoutCheckBoxChecked(int)));
}

DelegatedStaking::~DelegatedStaking() {
    delete ui;
}

void DelegatedStaking::setWalletModel(WalletModel *walletmodel) {
    if (!walletmodel)
        return;

    this->walletModel = walletmodel;
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

    Q_EMIT message(tr("Delegate Coins"), msgParams.first, msgParams.second);
}

void DelegatedStaking::on_sendButton_clicked()
{
    if(!walletModel)
        return;

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
                recipientElement = tr("%1 delegated to %2").arg(amount, GUIUtil::HtmlEscape(rcp.label));
                recipientElement.append(QString(" (%1)").arg(address));
            }
            else // just address
            {
                recipientElement = tr("%1 delegated to %2").arg(amount, address);
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

    std::shared_ptr<CReserveScript> coinbaseScript;
    walletModel->getWallet()->GetScriptForMining(coinbaseScript);
    if (!coinbaseScript) {
        return;// error("%s: Error: Keypool ran out, please call keypoolrefill first.", __func__);
    }
    if (coinbaseScript->reserveScript.empty()) {
        return;// error("%s: No coinbase script available.", __func__);
    }

    CScript  delegateScript = GetScriptForDestination(CBitcoinAddress(ui->delegateTo->text().toStdString()).Get());

    CScript scriptPubKeyKernel = coinbaseScript->reserveScript;
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
            Q_EMIT message(tr("Delegate Coins"), tr("Delegate fee percent is not valid"), CClientUIInterface::MSG_ERROR);
            return;
        }
        script << nFeePercent;
        script << OP_DROP;

        CBitcoinAddress delegateReward(ui->rewardTo->text().toStdString());
        if(!delegateReward.IsValid() || !delegateReward.IsScript()){
            Q_EMIT message(tr("Delegate Coins"), tr("Delegate reward address is not valid"), CClientUIInterface::MSG_ERROR);
            return;
        }

        //Returns false if not coldstake or p2sh script
        CScriptID destDelegateReward;
        if (!ExtractStakingKeyID(GetScriptForDestination(delegateReward.Get()), destDelegateReward)){
            Q_EMIT message(tr("Delegate Coins"), tr("ExtractStakingKeyID is not valid"), CClientUIInterface::MSG_ERROR);
            return;
        }

        script << ToByteVector(destDelegateReward);
        script << OP_DROP;
    }

    scriptPubKeyKernel = script;

    SendConfirmationDialog confirmationDialog(tr("Confirm delegate coins"),
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
        Q_EMIT message(tr("Delegate Coins"), tr(strError.c_str()), CClientUIInterface::MSG_ERROR);
        return;
    }
    CValidationState state;
    if (!walletModel->getWallet()->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
        Q_EMIT message(tr("Delegate Coins"), tr(strError.c_str()), CClientUIInterface::MSG_ERROR);
        return;
    }


    //accept();
    CoinControlDialog::coinControl()->UnSelectAll();
    //coinControlUpdateLabels();
}

