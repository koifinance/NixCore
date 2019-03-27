// Copyright (c) 2018-2019 The NIX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "offchaingovernance.h"
#include "governance/networking-governance.h"
#include "qt/forms/ui_offchaingovernance.h"

#include "clientmodel.h"
#include "init.h"
#include "guiutil.h"
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

OffChainGovernance::OffChainGovernance(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OffChainGovernance),
    clientModel(0),
    walletModel(0)
{
    ui->setupUi(this);

    int columnAliasWidth = 100;
    int columnAddressWidth = 200;
    int columnProtocolWidth = 60;
    int columnStatusWidth = 80;
    int columnActiveWidth = 130;
    int columnLastSeenWidth = 130;

    ui->tableWidgetProposals->setColumnWidth(0, columnAddressWidth);
    ui->tableWidgetProposals->setColumnWidth(1, columnProtocolWidth);
    ui->tableWidgetProposals->setColumnWidth(2, columnStatusWidth);
    ui->tableWidgetProposals->setColumnWidth(3, columnActiveWidth);
    ui->tableWidgetProposals->setColumnWidth(4, columnLastSeenWidth);

    QAction *startAliasAction = new QAction(tr("Start alias"), this);

    timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(updateProposalList()));
    timer->start(1000);

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
        // try to update list when Ghostnode count changes
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

    g_governance.GetRequests(RequestTypes::SUBMISSIONS);

    while(!g_governance.ready){}

    g_governance.ready = false;

    BOOST_FOREACH(Proposals & prop, g_governance.proposals)
    {
        QTableWidgetItem *nameItem = new QTableWidgetItem(QString::fromStdString(prop.name));
        QTableWidgetItem *detailsItem = new QTableWidgetItem(QString::fromStdString(prop.details));
        QTableWidgetItem *addressItem = new QTableWidgetItem(QString::fromStdString(prop.address));
        QTableWidgetItem *amountItem = new QTableWidgetItem(QString::fromStdString(prop.amount));
        QTableWidgetItem *txidItem = new QTableWidgetItem(QString::fromStdString(prop.txid));

        //QTableWidgetItem *amountItem = new QTableWidgetItem(QString::fromStdString(DurationToDHMS(mn.lastPing.sigTime - mn.sigTime)));
        //QTableWidgetItem *txidItem = new QTableWidgetItem(QString::fromStdString(DateTimeStrFormat("%Y-%m-%d %H:%M", mn.lastPing.sigTime + offsetFromUtc)));

        if (strCurrentFilter != "")
        {
            strToFilter =   nameItem->text() + " " +
                            detailsItem->text() + " " +
                            addressItem->text() + " " +
                            amountItem->text() + " " +
                            txidItem->text();
            if (!strToFilter.contains(strCurrentFilter)) continue;
        }

        ui->tableWidgetProposals->insertRow(0);
        ui->tableWidgetProposals->setItem(0, 0, nameItem);
        ui->tableWidgetProposals->setItem(0, 1, detailsItem);
        ui->tableWidgetProposals->setItem(0, 2, addressItem);
        ui->tableWidgetProposals->setItem(0, 3, amountItem);
        ui->tableWidgetProposals->setItem(0, 4, txidItem);
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
