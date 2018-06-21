#include "ghostnode.h"
#include "qt/forms/ui_ghostnode.h"

#include "ghostnode/activeghostnode.h"
#include "clientmodel.h"
#include "init.h"
#include "guiutil.h"
#include "ghostnode/ghostnode-sync.h"
#include "ghostnode/ghostnodeconfig.h"
#include "ghostnode/ghostnodeman.h"
#include "sync.h"
#include "wallet/wallet.h"
#include "walletmodel.h"
#include <boost/foreach.hpp>

#include <QTimer>
#include <QMessageBox>

int GetOffsetFromUtc()
{
#if QT_VERSION < 0x050200
    const QDateTime dateTime1 = QDateTime::currentDateTime();
    const QDateTime dateTime2 = QDateTime(dateTime1.date(), dateTime1.time(), Qt::UTC);
    return dateTime1.secsTo(dateTime2);
#else
    return QDateTime::currentDateTime().offsetFromUtc();
#endif
}

GhostNode::GhostNode(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::GhostNode),
    clientModel(0),
    walletModel(0)
{
    ui->setupUi(this);

    ui->startButton->setEnabled(false);

    int columnAliasWidth = 100;
    int columnAddressWidth = 200;
    int columnProtocolWidth = 60;
    int columnStatusWidth = 80;
    int columnActiveWidth = 130;
    int columnLastSeenWidth = 130;

    ui->tableWidgetMyGhostnodes->setColumnWidth(0, columnAliasWidth);
    ui->tableWidgetMyGhostnodes->setColumnWidth(1, columnAddressWidth);
    ui->tableWidgetMyGhostnodes->setColumnWidth(2, columnProtocolWidth);
    ui->tableWidgetMyGhostnodes->setColumnWidth(3, columnStatusWidth);
    ui->tableWidgetMyGhostnodes->setColumnWidth(4, columnActiveWidth);
    ui->tableWidgetMyGhostnodes->setColumnWidth(5, columnLastSeenWidth);

    ui->tableWidgetGhostnodes->setColumnWidth(0, columnAddressWidth);
    ui->tableWidgetGhostnodes->setColumnWidth(1, columnProtocolWidth);
    ui->tableWidgetGhostnodes->setColumnWidth(2, columnStatusWidth);
    ui->tableWidgetGhostnodes->setColumnWidth(3, columnActiveWidth);
    ui->tableWidgetGhostnodes->setColumnWidth(4, columnLastSeenWidth);

    ui->tableWidgetMyGhostnodes->setContextMenuPolicy(Qt::CustomContextMenu);

    QAction *startAliasAction = new QAction(tr("Start alias"), this);
    contextMenu = new QMenu();
    contextMenu->addAction(startAliasAction);
    connect(ui->tableWidgetMyGhostnodes, SIGNAL(customContextMenuRequested(const QPoint&)), this, SLOT(showContextMenu(const QPoint&)));
    connect(startAliasAction, SIGNAL(triggered()), this, SLOT(on_startButton_clicked()));

    timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(updateNodeList()));
    connect(timer, SIGNAL(timeout()), this, SLOT(updateMyNodeList()));
    timer->start(1000);

    fFilterUpdated = false;
    nTimeFilterUpdated = GetTime();
    updateNodeList();
}

GhostNode::~GhostNode()
{
    delete ui;
}

void GhostNode::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model) {
        // try to update list when Ghostnode count changes
        connect(clientModel, SIGNAL(strGhostnodesChanged(QString)), this, SLOT(updateNodeList()));
    }
}

void GhostNode::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
}

void GhostNode::showContextMenu(const QPoint &point)
{
    QTableWidgetItem *item = ui->tableWidgetMyGhostnodes->itemAt(point);
    if(item) contextMenu->exec(QCursor::pos());
}

void GhostNode::StartAlias(std::string strAlias)
{
    std::string strStatusHtml;
    strStatusHtml += "<center>Alias: " + strAlias;

    BOOST_FOREACH(CGhostnodeConfig::CGhostnodeEntry mne, ghostnodeConfig.getEntries()) {
        if(mne.getAlias() == strAlias) {
            std::string strError;
            CGhostnodeBroadcast mnb;

            bool fSuccess = CGhostnodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), strError, mnb);

            if(fSuccess) {
                strStatusHtml += "<br>Successfully started ghostnode.";
                mnodeman.UpdateGhostnodeList(mnb);
                mnb.RelayGhostNode();
                mnodeman.NotifyGhostnodeUpdates();
            } else {
                strStatusHtml += "<br>Failed to start ghostnode.<br>Error: " + strError;
            }
            break;
        }
    }
    strStatusHtml += "</center>";

    QMessageBox msg;
    msg.setText(QString::fromStdString(strStatusHtml));
    msg.exec();

    updateMyNodeList(true);
}

void GhostNode::StartAll(std::string strCommand)
{
    int nCountSuccessful = 0;
    int nCountFailed = 0;
    std::string strFailedHtml;

    BOOST_FOREACH(CGhostnodeConfig::CGhostnodeEntry mne, ghostnodeConfig.getEntries()) {
        std::string strError;
        CGhostnodeBroadcast mnb;

        int32_t nOutputIndex = 0;
        if(!ParseInt32(mne.getOutputIndex(), &nOutputIndex)) {
            continue;
        }

        COutPoint outpoint = COutPoint(uint256S(mne.getTxHash()), nOutputIndex);

        if(strCommand == "start-missing" && mnodeman.Has(CTxIn(outpoint))) continue;

        bool fSuccess = CGhostnodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), strError, mnb);

        if(fSuccess) {
            nCountSuccessful++;
            mnodeman.UpdateGhostnodeList(mnb);
            mnb.RelayGhostNode();
            mnodeman.NotifyGhostnodeUpdates();
        } else {
            nCountFailed++;
            strFailedHtml += "\nFailed to start " + mne.getAlias() + ". Error: " + strError;
        }
    }
    walletModel->getWallet()->Lock();

    std::string returnObj;
    returnObj = strprintf("Successfully started %d ghostnodes, failed to start %d, total %d", nCountSuccessful, nCountFailed, nCountFailed + nCountSuccessful);
    if (nCountFailed > 0) {
        returnObj += strFailedHtml;
    }

    QMessageBox msg;
    msg.setText(QString::fromStdString(returnObj));
    msg.exec();

    updateMyNodeList(true);
}

void GhostNode::updateMyGhostnodeInfo(QString strAlias, QString strAddr, const COutPoint& outpoint)
{
    bool fOldRowFound = false;
    int nNewRow = 0;

    for(int i = 0; i < ui->tableWidgetMyGhostnodes->rowCount(); i++) {
        if(ui->tableWidgetMyGhostnodes->item(i, 0)->text() == strAlias) {
            fOldRowFound = true;
            nNewRow = i;
            break;
        }
    }

    if(nNewRow == 0 && !fOldRowFound) {
        nNewRow = ui->tableWidgetMyGhostnodes->rowCount();
        ui->tableWidgetMyGhostnodes->insertRow(nNewRow);
    }

    ghostnode_info_t infoMn = mnodeman.GetGhostnodeInfo(CTxIn(outpoint));
    bool fFound = infoMn.fInfoValid;

    QTableWidgetItem *aliasItem = new QTableWidgetItem(strAlias);
    QTableWidgetItem *addrItem = new QTableWidgetItem(fFound ? QString::fromStdString(infoMn.addr.ToString()) : strAddr);
    QTableWidgetItem *protocolItem = new QTableWidgetItem(QString::number(fFound ? infoMn.nProtocolVersion : -1));
    QTableWidgetItem *statusItem = new QTableWidgetItem(QString::fromStdString(fFound ? CGhostnode::StateToString(infoMn.nActiveState) : "MISSING"));
    QTableWidgetItem *activeSecondsItem = new QTableWidgetItem(QString::fromStdString(DurationToDHMS(fFound ? (infoMn.nTimeLastPing - infoMn.sigTime) : 0)));
    QTableWidgetItem *lastSeenItem = new QTableWidgetItem(QString::fromStdString(DateTimeStrFormat("%Y-%m-%d %H:%M",
                                                                                                   fFound ? infoMn.nTimeLastPing + GetOffsetFromUtc() : 0)));
    QTableWidgetItem *pubkeyItem = new QTableWidgetItem(QString::fromStdString(fFound ? CBitcoinAddress(infoMn.pubKeyCollateralAddress.GetID()).ToString() : ""));

    ui->tableWidgetMyGhostnodes->setItem(nNewRow, 0, aliasItem);
    ui->tableWidgetMyGhostnodes->setItem(nNewRow, 1, addrItem);
    ui->tableWidgetMyGhostnodes->setItem(nNewRow, 2, protocolItem);
    ui->tableWidgetMyGhostnodes->setItem(nNewRow, 3, statusItem);
    ui->tableWidgetMyGhostnodes->setItem(nNewRow, 4, activeSecondsItem);
    ui->tableWidgetMyGhostnodes->setItem(nNewRow, 5, lastSeenItem);
    ui->tableWidgetMyGhostnodes->setItem(nNewRow, 6, pubkeyItem);
}

void GhostNode::updateMyNodeList(bool fForce)
{
    TRY_LOCK(cs_mymnlist, fLockAcquired);
    if(!fLockAcquired) {
        return;
    }
    static int64_t nTimeMyListUpdated = 0;

    // automatically update my ghostnode list only once in MY_MASTERNODELIST_UPDATE_SECONDS seconds,
    // this update still can be triggered manually at any time via button click
    int64_t nSecondsTillUpdate = nTimeMyListUpdated + MY_MASTERNODELIST_UPDATE_SECONDS - GetTime();
    ui->secondsLabel->setText(QString::number(nSecondsTillUpdate));

    if(nSecondsTillUpdate > 0 && !fForce) return;
    nTimeMyListUpdated = GetTime();

    ui->tableWidgetGhostnodes->setSortingEnabled(false);
    BOOST_FOREACH(CGhostnodeConfig::CGhostnodeEntry mne, ghostnodeConfig.getEntries()) {
        int32_t nOutputIndex = 0;
        if(!ParseInt32(mne.getOutputIndex(), &nOutputIndex)) {
            continue;
        }

        updateMyGhostnodeInfo(QString::fromStdString(mne.getAlias()), QString::fromStdString(mne.getIp()), COutPoint(uint256S(mne.getTxHash()), nOutputIndex));
    }
    ui->tableWidgetGhostnodes->setSortingEnabled(true);

    // reset "timer"
    ui->secondsLabel->setText("0");
}

void GhostNode::updateNodeList()
{
    TRY_LOCK(cs_mnlist, fLockAcquired);
    if(!fLockAcquired) {
        return;
    }

    static int64_t nTimeListUpdated = GetTime();

    // to prevent high cpu usage update only once in MASTERNODELIST_UPDATE_SECONDS seconds
    // or MASTERNODELIST_FILTER_COOLDOWN_SECONDS seconds after filter was last changed
    int64_t nSecondsToWait = fFilterUpdated
                            ? nTimeFilterUpdated - GetTime() + MASTERNODELIST_FILTER_COOLDOWN_SECONDS
                            : nTimeListUpdated - GetTime() + MASTERNODELIST_UPDATE_SECONDS;

    if(fFilterUpdated) ui->countLabel->setText(QString::fromStdString(strprintf("Please wait... %d", nSecondsToWait)));
    if(nSecondsToWait > 0) return;

    nTimeListUpdated = GetTime();
    fFilterUpdated = false;

    QString strToFilter;
    ui->countLabel->setText("Updating...");
    ui->tableWidgetGhostnodes->setSortingEnabled(false);
    ui->tableWidgetGhostnodes->clearContents();
    ui->tableWidgetGhostnodes->setRowCount(0);
//    std::map<COutPoint, CGhostnode> mapGhostnodes = mnodeman.GetFullGhostnodeMap();
    std::vector<CGhostnode> vGhostnodes = mnodeman.GetFullGhostnodeVector();
    int offsetFromUtc = GetOffsetFromUtc();

    BOOST_FOREACH(CGhostnode & mn, vGhostnodes)
    {
//        CGhostnode mn = mnpair.second;
        // populate list
        // Address, Protocol, Status, Active Seconds, Last Seen, Pub Key
        QTableWidgetItem *addressItem = new QTableWidgetItem(QString::fromStdString(mn.addr.ToString()));
        QTableWidgetItem *protocolItem = new QTableWidgetItem(QString::number(mn.nProtocolVersion));
        QTableWidgetItem *statusItem = new QTableWidgetItem(QString::fromStdString(mn.GetStatus()));
        QTableWidgetItem *activeSecondsItem = new QTableWidgetItem(QString::fromStdString(DurationToDHMS(mn.lastPing.sigTime - mn.sigTime)));
        QTableWidgetItem *lastSeenItem = new QTableWidgetItem(QString::fromStdString(DateTimeStrFormat("%Y-%m-%d %H:%M", mn.lastPing.sigTime + offsetFromUtc)));
        QTableWidgetItem *pubkeyItem = new QTableWidgetItem(QString::fromStdString(CBitcoinAddress(mn.pubKeyCollateralAddress.GetID()).ToString()));

        if (strCurrentFilter != "")
        {
            strToFilter =   addressItem->text() + " " +
                            protocolItem->text() + " " +
                            statusItem->text() + " " +
                            activeSecondsItem->text() + " " +
                            lastSeenItem->text() + " " +
                            pubkeyItem->text();
            if (!strToFilter.contains(strCurrentFilter)) continue;
        }

        ui->tableWidgetGhostnodes->insertRow(0);
        ui->tableWidgetGhostnodes->setItem(0, 0, addressItem);
        ui->tableWidgetGhostnodes->setItem(0, 1, protocolItem);
        ui->tableWidgetGhostnodes->setItem(0, 2, statusItem);
        ui->tableWidgetGhostnodes->setItem(0, 3, activeSecondsItem);
        ui->tableWidgetGhostnodes->setItem(0, 4, lastSeenItem);
        ui->tableWidgetGhostnodes->setItem(0, 5, pubkeyItem);
    }

    ui->countLabel->setText(QString::number(ui->tableWidgetGhostnodes->rowCount()));
    ui->tableWidgetGhostnodes->setSortingEnabled(true);
}

void GhostNode::on_filterLineEdit_textChanged(const QString &strFilterIn)
{
    strCurrentFilter = strFilterIn;
    nTimeFilterUpdated = GetTime();
    fFilterUpdated = true;
    ui->countLabel->setText(QString::fromStdString(strprintf("Please wait... %d", MASTERNODELIST_FILTER_COOLDOWN_SECONDS)));
}

void GhostNode::on_startButton_clicked()
{
    std::string strAlias;
    {
        LOCK(cs_mymnlist);
        // Find selected node alias
        QItemSelectionModel* selectionModel = ui->tableWidgetMyGhostnodes->selectionModel();
        QModelIndexList selected = selectionModel->selectedRows();

        if(selected.count() == 0) return;

        QModelIndex index = selected.at(0);
        int nSelectedRow = index.row();
        strAlias = ui->tableWidgetMyGhostnodes->item(nSelectedRow, 0)->text().toStdString();
    }

    // Display message box
    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm ghostnode start"),
        tr("Are you sure you want to start ghostnode %1?").arg(QString::fromStdString(strAlias)),
        QMessageBox::Yes | QMessageBox::Cancel,
        QMessageBox::Cancel);

    if(retval != QMessageBox::Yes) return;

    WalletModel::EncryptionStatus encStatus = walletModel->getEncryptionStatus();

    if(encStatus == walletModel->Locked || encStatus == walletModel->UnlockedForMixingOnly) {
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());

        if(!ctx.isValid()) return; // Unlock wallet was cancelled

        StartAlias(strAlias);
        return;
    }

    StartAlias(strAlias);
}

void GhostNode::on_startAllButton_clicked()
{
    // Display message box
    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm all ghostnode start"),
        tr("Are you sure you want to start ALL ghostnodes?"),
        QMessageBox::Yes | QMessageBox::Cancel,
        QMessageBox::Cancel);

    if(retval != QMessageBox::Yes) return;

    WalletModel::EncryptionStatus encStatus = walletModel->getEncryptionStatus();

    if(encStatus == walletModel->Locked || encStatus == walletModel->UnlockedForMixingOnly) {
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());

        if(!ctx.isValid()) return; // Unlock wallet was cancelled

        StartAll();
        return;
    }

    StartAll();
}

void GhostNode::on_startMissingButton_clicked()
{

    if(!ghostnodeSync.IsGhostnodeListSynced()) {
        QMessageBox::critical(this, tr("Command is not available right now"),
            tr("You can't use this command until ghostnode list is synced"));
        return;
    }

    // Display message box
    QMessageBox::StandardButton retval = QMessageBox::question(this,
        tr("Confirm missing ghostnodes start"),
        tr("Are you sure you want to start MISSING ghostnodes?"),
        QMessageBox::Yes | QMessageBox::Cancel,
        QMessageBox::Cancel);

    if(retval != QMessageBox::Yes) return;

    WalletModel::EncryptionStatus encStatus = walletModel->getEncryptionStatus();

    if(encStatus == walletModel->Locked || encStatus == walletModel->UnlockedForMixingOnly) {
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());

        if(!ctx.isValid()) return; // Unlock wallet was cancelled

        StartAll("start-missing");
        return;
    }

    StartAll("start-missing");
}

void GhostNode::on_tableWidgetMyGhostnodes_itemSelectionChanged()
{
    if(ui->tableWidgetMyGhostnodes->selectedItems().count() > 0) {
        ui->startButton->setEnabled(true);
    }
}

void GhostNode::on_UpdateButton_clicked()
{
    updateMyNodeList(true);
}
