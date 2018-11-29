// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NIX_QT_DELEGATEDSTAKING_H
#define NIX_QT_DELEGATEDSTAKING_H

#include <QWidget>
#include <QTableWidget>
#include <amount.h>
#include <qt/walletmodel.h>

class AddressTableModel;
class OptionsModel;
class PlatformStyle;
class WalletModel;
class COutPoint;

namespace Ui {
    class DelegatedStaking;
}

QT_BEGIN_NAMESPACE
class QItemSelection;
class QMenu;
class QModelIndex;
class QSortFilterProxyModel;
class QTableView;
QT_END_NAMESPACE

/** Widget that shows a list of sending or receiving addresses.
  */
class DelegatedStaking : public QWidget
{
    Q_OBJECT

public:

    enum Mode {
        ForSelection, /**< Open address book to pick address */
        ForEditing  /**< Open address book for editing */
    };

    explicit DelegatedStaking(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~DelegatedStaking();

    void setWalletModel(WalletModel *walletmodel);
    const QString &getReturnValue() const { return returnValue; }
    void setVaultBalance(CAmount confirmed, CAmount unconfirmed);
    void setKeyList();

private:
    Ui::DelegatedStaking *ui;
    AddressTableModel *model;
    WalletModel *walletModel;
    Mode mode;
    QString returnValue;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *deleteAction; // to be able to explicitly disable it
    QString newAddressToSelect;
    QModelIndex selectedRow();
    const PlatformStyle *platformStyle;
    std::vector <COutPoint> activeContractsOutpoints;
    std::vector <CAmount> activeContractsAmounts;

    void processDelegatedCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg = QString());
    void updateContractList();

private Q_SLOTS:
    /** Send button clicked */
    void on_sendButton_clicked();
    /** Fee Payout checked */
    void enableFeePayoutCheckBoxChecked(int);

    void cancelContract();

    void showContextMenu(const QPoint &);

Q_SIGNALS:
    void message(const QString &title, const QString &message, unsigned int style);
};


#endif // DELEGATEDSTAKING_H
