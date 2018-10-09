// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_GHOSTVAULT_H
#define BITCOIN_QT_GHOSTVAULT_H

#include <QWidget>
#include <amount.h>

class AddressTableModel;
class OptionsModel;
class PlatformStyle;
class WalletModel;

namespace Ui {
    class GhostVault;
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
class GhostVault : public QWidget
{
    Q_OBJECT

public:

    enum Mode {
        ForSelection, /**< Open address book to pick address */
        ForEditing  /**< Open address book for editing */
    };

    explicit GhostVault(const PlatformStyle *platformStyle, Mode mode, QWidget *parent);
    ~GhostVault();

    void setModel(AddressTableModel *model);
    void setWalletModel(WalletModel *walletmodel);
    const QString &getReturnValue() const { return returnValue; }
    void setVaultBalance(CAmount confirmed, CAmount unconfirmed);

//public Q_SLOTS:
//    void done(int retval);

private:
    Ui::GhostVault *ui;
    AddressTableModel *model;
    WalletModel *walletModel;
    Mode mode;
    QString returnValue;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *deleteAction; // to be able to explicitly disable it
    QString newAddressToSelect;

private Q_SLOTS:
    /** Export button clicked */
    void on_exportButton_clicked();
    /** Ghost NIX clicked */
    void on_ghostNIXButton_clicked();
    /** Ghost convert clicked */
    void on_convertGhostButton_clicked();
    /** Ghost transfer clicked */
    void on_transferGhostButton_clicked();
    /** Ghost To Me checked */
    void convertGhostToMeCheckBoxChecked(int);
//    void on_showQRCode_clicked();
    /** Set button states based on selected tab and selection */
//    void selectionChanged();
    /** Spawn contextual menu (right mouse menu) for address book entry */
    void contextualMenu(const QPoint &point);
    /** New entry/entries were added to address table */
    void selectNewAddress(const QModelIndex &parent, int begin, int /*end*/);

Q_SIGNALS:
    void sendCoins(QString addr);
};

#endif // BITCOIN_QT_ADDRESSBOOKPAGE_H
