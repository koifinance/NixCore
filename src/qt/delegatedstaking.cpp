// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/nix-config.h"
#endif

#include <qt/delegatedstaking.h>
#include <qt/forms/ui_delegatedstaking.h>


#include "addresstablemodel.h"
#include "walletmodel.h"
#include "nixgui.h"
#include "csvmodelwriter.h"
#include "editaddressdialog.h"
#include "guiutil.h"
#include "platformstyle.h"
#include <wallet/wallet.h>
#include "qt/recentrequeststablemodel.h"
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

DelegatedStaking::DelegatedStaking(const PlatformStyle *platformStyle, Mode mode, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::DelegatedStaking),
    model(0),
    mode(mode)
{

    ui->setupUi(this);

    setWindowTitle(tr("Delegated Staking"));

    QDoubleValidator *doubleValidator= new QDoubleValidator(this);
    doubleValidator->setBottom(0.00);
    doubleValidator->setDecimals(2);
    doubleValidator->setTop(100.00);
    doubleValidator->setNotation(QDoubleValidator::StandardNotation);

    ui->feePercent->setValidator(doubleValidator);

    ui->labelExplanation->setTextFormat(Qt::RichText);
    ui->labelExplanation->setText(
                tr("Create DPoS smart contracts straight from your wallet."));

    ui->enableFeePayout->setVisible(true);

    connect(ui->sendButton, SIGNAL(triggered()), this, SLOT(on_sendButton_clicked()));

    connect(ui->enableFeePayout, SIGNAL(stateChanged(int)), this, SLOT(enableFeePayoutCheckBoxChecked(int)));
}

DelegatedStaking::~DelegatedStaking() {
    delete ui;
}

void DelegatedStaking::enableFeePayoutCheckBoxChecked(int state){
    if (state == Qt::Checked)
    {
        ui->feePercent->clear();
        ui->rewardTo->clear();
        ui->feePercent->setEnabled(false);
        ui->rewardTo->setEnabled(false);
    }else{
        ui->feePercent->setEnabled(true);
        ui->rewardTo->setEnabled(true);
    }
}
