// Copyright (c) 2018-2019 The NIX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OFFCHAIN_GOV_H
#define OFFCHAIN_GOV_H

#include "primitives/transaction.h"
#include "platformstyle.h"
#include "sync.h"
#include "util.h"

#include <QMenu>
#include <QTimer>
#include <QWidget>

#define UPDATE_SECONDS                    15
#define FILTER_COOLDOWN_SECONDS            3

namespace Ui {
    class OffChainGovernance;
}

class ClientModel;
class WalletModel;

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** OffChainGovernance Manager page widget */
class OffChainGovernance : public QWidget
{
    Q_OBJECT

public:
    explicit OffChainGovernance(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~OffChainGovernance();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);

private:
    QMenu *contextMenu;
    int64_t nTimeFilterUpdated;
    bool fFilterUpdated;
    QModelIndex selectedRow();

public Q_SLOTS:
    void updateProposalList();

Q_SIGNALS:

private:
    QTimer *timer;
    Ui::OffChainGovernance *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;

    CCriticalSection cs_mnlist;

    QString strCurrentFilter;

private Q_SLOTS:
    void on_filterLineEdit_textChanged(const QString &strFilterIn);
    void on_expandProposalButton_clicked();
    void on_tableWidgetProposals_doubleClicked(const QModelIndex &index);
    void on_voteForButton_clicked();
    void on_voteAgainstButton_clicked();
    void showMenu(const QPoint &point);
    void vote(std::string decision);


};
#endif // OFFCHAIN_GOV_H
