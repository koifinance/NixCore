// Copyright (c) 2018-2019 The NIX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <qt/offchaingovernance.h>
#include <governance/networking-governance.h>
#include <qt/forms/ui_offchaingovernance.h>
#include <qt/transactiondescdialog.h>
#include <qt/sendcoinsdialog.h>

#include <qt/clientmodel.h>
#include <ui_interface.h>
#include <init.h>
#include <qt/guiutil.h>
#include <sync.h>
#include <wallet/wallet.h>
#include <qt/walletmodel.h>
#include <boost/foreach.hpp>
#include <string>

#include <QTimer>
#include <QMessageBox>

OffChainGovernance::OffChainGovernance(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OffChainGovernance),
    clientModel(0),
    walletModel(0)
{
    ui->setupUi(this);

    ui->tableWidgetProposals->setColumnWidth(0, 200);
    ui->tableWidgetProposals->setColumnWidth(1, 140);
    ui->tableWidgetProposals->setColumnWidth(2, 80);
    ui->tableWidgetProposals->setColumnWidth(3, 80);
    ui->tableWidgetProposals->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    ui->tableWidgetProposals->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Fixed);
    ui->tableWidgetProposals->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Fixed);
    ui->tableWidgetProposals->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Fixed);
    ui->tableWidgetProposals->horizontalHeader()->setStretchLastSection(false);


    // context menu
    //contextMenu = new QMenu(this);
    //contextMenu->addAction(voteForAction);
    //contextMenu->addAction(voteAgainstAction);

    timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(updateProposalList()));
    timer->start(1000);
    // context menu signals
    connect(ui->tableWidgetProposals, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showMenu(QPoint)));

    fFilterUpdated = false;
    nTimeFilterUpdated = GetTime();
    updateProposalList();
}

OffChainGovernance::~OffChainGovernance()
{
    delete ui;
}

void OffChainGovernance::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model) {
        // try to update list when count changes
        connect(clientModel, SIGNAL(strGhostnodesChanged(QString)), this, SLOT(updateProposalList()));
    }
}

void OffChainGovernance::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
}

void OffChainGovernance::updateProposalList()
{
    TRY_LOCK(cs_mnlist, fLockAcquired);
    if(!fLockAcquired) {
        return;
    }

    static int64_t nTimeListUpdated = GetTime();

    // to prevent high cpu usage update only once in MASTERNODELIST_UPDATE_SECONDS seconds
    // or MASTERNODELIST_FILTER_COOLDOWN_SECONDS seconds after filter was last changed
    int64_t nSecondsToWait = fFilterUpdated
                            ? nTimeFilterUpdated - GetTime() + FILTER_COOLDOWN_SECONDS
                            : nTimeListUpdated - GetTime() + UPDATE_SECONDS;

    if(fFilterUpdated) ui->countLabel->setText(QString::fromStdString(strprintf("Please wait... %d", nSecondsToWait)));
    if(nSecondsToWait > 0) return;

    nTimeListUpdated = GetTime();
    fFilterUpdated = false;

    QString strToFilter;
    ui->countLabel->setText("Updating...");
    ui->tableWidgetProposals->setSortingEnabled(false);
    ui->tableWidgetProposals->clearContents();
    ui->tableWidgetProposals->setRowCount(0);

    g_governance.SendRequests(RequestTypes::GET_PROPOSALS);

    BOOST_FOREACH(Proposals & prop, g_governance.proposals)
    {
        QTableWidgetItem *nameItem = new QTableWidgetItem(QString::fromStdString(prop.name));
        QTableWidgetItem *amountItem = new QTableWidgetItem(QString::fromStdString(prop.amount));
        QTableWidgetItem *affirmItem = new QTableWidgetItem(QString::fromStdString(prop.votes_affirm));
        QTableWidgetItem *opposeItem = new QTableWidgetItem(QString::fromStdString(prop.votes_oppose));

        //QTableWidgetItem *amountItem = new QTableWidgetItem(QString::fromStdString(DurationToDHMS(mn.lastPing.sigTime - mn.sigTime)));
        //QTableWidgetItem *txidItem = new QTableWidgetItem(QString::fromStdString(DateTimeStrFormat("%Y-%m-%d %H:%M", mn.lastPing.sigTime + offsetFromUtc)));

        if (strCurrentFilter != "")
        {
            strToFilter =   nameItem->text() + " " +
                            amountItem->text() + " " +
                            affirmItem->text() + " " +
                            opposeItem->text();
            if (!strToFilter.contains(strCurrentFilter)) continue;
        }

        ui->tableWidgetProposals->insertRow(0);
        ui->tableWidgetProposals->setItem(0, 0, nameItem);
        ui->tableWidgetProposals->setItem(0, 1, amountItem);
        ui->tableWidgetProposals->setItem(0, 2, affirmItem);
        ui->tableWidgetProposals->setItem(0, 3, opposeItem);
    }

    ui->countLabel->setText(QString::number(ui->tableWidgetProposals->rowCount()));
    ui->tableWidgetProposals->setSortingEnabled(true);
}

void OffChainGovernance::on_filterLineEdit_textChanged(const QString &strFilterIn)
{
    strCurrentFilter = strFilterIn;
    nTimeFilterUpdated = GetTime();
    fFilterUpdated = true;
    ui->countLabel->setText(QString::fromStdString(strprintf("Please wait... %d", FILTER_COOLDOWN_SECONDS)));
}

void OffChainGovernance::on_tableWidgetProposals_doubleClicked(const QModelIndex &index)
{
    QModelIndexList selection = ui->tableWidgetProposals->selectionModel()->selectedRows();
    if(!selection.isEmpty())
    {
        TransactionDescDialog *dlg = new TransactionDescDialog(selection.at(0));
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        std::string name = selection.at(0).data(0).toString().toStdString();
        Proposals selectedProp;
        for(Proposals proposals: g_governance.proposals){
            if(name == proposals.name){
                selectedProp = proposals;
                break;
            }
        }
        QString desc = tr("Name: ") + QString::fromStdString(selectedProp.name) + tr("\n\n") +
                tr("Details: ") + QString::fromStdString(selectedProp.details) + tr("\n\n") +
                tr("Address: ") + QString::fromStdString(selectedProp.address) + tr("\n\n") +
                tr("Amount: ") + QString::fromStdString(selectedProp.amount) + tr("\n\n") +
                tr("TxID: ") + QString::fromStdString(selectedProp.txid) + tr("\n\n") +
                tr("Votes Affirm: ") + QString::fromStdString(selectedProp.votes_affirm) + tr("\n\n") +
                tr("Votes Oppose: ") + QString::fromStdString(selectedProp.votes_oppose) + tr("\n");


        dlg->SetWindowTitle(selection.at(0).data(0).toString());
        dlg->SetText(desc);
        dlg->show();
    }
}

void OffChainGovernance::on_expandProposalButton_clicked()
{
    if(!walletModel || !walletModel->getRecentRequestsTableModel() || !ui->tableWidgetProposals->selectionModel())
        return;

    QModelIndexList selection = ui->tableWidgetProposals->selectionModel()->selectedRows();

    for (const QModelIndex& index : selection) {
        on_tableWidgetProposals_doubleClicked(index);
    }
}

QModelIndex OffChainGovernance::selectedRow()
{
    if(!ui->tableWidgetProposals->selectionModel())
        return QModelIndex();
    QModelIndexList selection = ui->tableWidgetProposals->selectionModel()->selectedRows();
    if(selection.empty())
        return QModelIndex();
    // correct for selection mode ContiguousSelection
    QModelIndex firstIndex = selection.at(0);
    return firstIndex;
}

// context menu
void OffChainGovernance::showMenu(const QPoint &point)
{
    if (!selectedRow().isValid()) {
        return;
    }
    contextMenu->exec(QCursor::pos());
}

void OffChainGovernance::vote(std::string decision)
{
    QModelIndex sel = selectedRow();
    if (!sel.isValid()) {
        return;
    }

    CWallet *pwallet = walletModel->getWallet();

    LOCK2(cs_main, pwallet->cs_wallet);

    CWalletDB walletdb(pwallet->GetDBHandle());


    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if(!ctx.isValid())
    {
        // Unlock wallet was cancelled
        return;
    }

    std::string name = sel.data(0).toString().toStdString();
    Proposals selectedProp;
    for(Proposals proposals: g_governance.proposals){
        if(name == proposals.name){
            selectedProp = proposals;
            break;
        }
    }

    std::string postMessage;
    std::string vote_id = selectedProp.vote_id;

    std::list<CGovernanceEntry> govEntries;
    walletdb.ListGovernanceEntries(govEntries);

    for(auto entry: govEntries){
        // make sure we are not voting for a proposal we have voted for already
        if(vote_id == entry.voteID){
            Q_EMIT message(tr("Cast Vote"), tr("You have already voted for this proposal!\nYour vote weight: ") + tr(std::to_string(entry.voteWeight).c_str()), CClientUIInterface::MSG_ERROR);
            return;
        }
    }

    QString textOption;
    if(decision == "0")
        textOption = "against ";
    else
        textOption = "for ";

    QString detail = "<span style='font-family: monospace;'>Are you sure you want to vote " + textOption + QString::fromStdString(name) + "? This action cannot be reversed.";
    detail.append("</span>");

    SendConfirmationDialog confirmationDialog(tr("Cast vote for ") + QString::fromStdString(selectedProp.name),
        detail, SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

    if(retval != QMessageBox::Yes)
    {
        return;
    }

    // Cycle through all transactions and log all addresses
    std::vector<CScript> votingAddresses;
    votingAddresses.clear();
    for (auto& mapping: pwallet->mapWallet){
        CWalletTx wtx = mapping.second;

        if(!wtx.IsCoinStake())
            continue;


        // check for multiple outputs
        for(auto& vout: wtx.tx->vout){

            if (!::IsMine(*pwallet, vout.scriptPubKey)) continue;

            // skip p2sh, only bech32/legacy allowed
            if(vout.scriptPubKey.IsPayToScriptHashAny())
                continue;

            if (std::find(votingAddresses.begin(), votingAddresses.end(), vout.scriptPubKey) != votingAddresses.end())
                continue;

            // store unique values
            votingAddresses.push_back(vout.scriptPubKey);
        }

    }

    postMessage = "[";

    int id = 0;

    for(auto &addrScript: votingAddresses){

        CTxDestination dest;
        ExtractDestination(addrScript, dest);

        std::string strAddress = EncodeDestination(dest);
        std::string strMessage = vote_id;

        if (!IsValidDestination(dest)) {
            Q_EMIT message(tr("Cast Vote"), tr("Address decoding issue."), CClientUIInterface::MSG_ERROR);
            return;
        }

        const CKeyID keyID = GetKeyForDestination(*pwallet, dest);
        if (keyID.IsNull()) {
            Q_EMIT message(tr("Cast Vote"), tr("Cannot extract address key ID's."), CClientUIInterface::MSG_ERROR);
            return;
        }

        CKey key;
        if (!pwallet->GetKey(keyID, key)) {
            Q_EMIT message(tr("Cast Vote"), tr("Cannot get wallet key."), CClientUIInterface::MSG_ERROR);
            return;
        }

        CHashWriter ss(SER_GETHASH, 0);
        ss << strMessageMagic;
        ss << strMessage;

        std::vector<unsigned char> vchSig;
        if (!key.SignCompact(ss.GetHash(), vchSig)){
            Q_EMIT message(tr("Cast Vote"), tr("Cannot create signature."), CClientUIInterface::MSG_ERROR);
            return;
        }

        if(id != 0)
            postMessage += ",";

        postMessage += "{"
                       "\"voteid\":\"" + vote_id +
                        "\",\"address\":\"" + strAddress +
                        "\",\"signature\":\"" + EncodeBase64(vchSig.data(), vchSig.size()) +
                        "\",\"ballot\":\"" + decision + "\"}";

        id++;

    }


    postMessage += "]";

    g_governance.SendRequests(RequestTypes::CAST_VOTE, postMessage);

    while(!g_governance.isReady()){}

    // store vote only on successfull request
    if(!g_governance.statusOK){
        Q_EMIT message(tr("Cast Vote"), tr("Vote not successful."), CClientUIInterface::MSG_ERROR);
        return;
    }

    CAmount voteWeight = 0;
    for(int i = 0; i < g_governance.votes.size(); i++){
        if(g_governance.votes[i].vote_id != vote_id)
            continue;

        voteWeight += std::stoi(g_governance.votes[i].weight);
    }

    if(voteWeight != 0){
        // place vote into wallet db for future reference
        CGovernanceEntry govVote;
        govVote.voteID = vote_id;
        govVote.voteWeight = voteWeight;
        walletdb.WriteGovernanceEntry(govVote);
    }

    return;
}

void OffChainGovernance::on_voteForButton_clicked()
{
    if(!ui->tableWidgetProposals->selectionModel())
        return;

    if (!selectedRow().isValid()) {
        return;
    }

    vote("1");
}

void OffChainGovernance::on_voteAgainstButton_clicked()
{
    if(!ui->tableWidgetProposals->selectionModel())
        return;

    if (!selectedRow().isValid()) {
        return;
    }

    vote("0");
}
