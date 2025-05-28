from PyQt5.QtWidgets import QMessageBox, QMainWindow, QDialog, QWidget
from PyQt5 import QtWidgets, QtGui
from dataclasses import dataclass, asdict
import MainWindowUI, AddRuleWindowUI
import json
import sys
import iptablesControl  # Import iptables control module
import os
#os.environ['QT_QPA_PLATFORM'] = 'xcb'

service_to_port = {
    "HTTP": ["TCP", "80"],
    "HTTPS": ["TCP", "443"],
    "SSH": ["TCP", "22"],
    "FTP": ["TCP", "21"],
    "SMTP": ["TCP", "25"],
    "DNS": ["UDP", "53"],
    "TELNET": ["TCP", "23"],
}

@dataclass
class Rule():
    ip: str
    IPmask: str
    port: str
    limit: int
    protocol: str

class RuleList():
    def __init__(self):
        self.rules = []
        try:
            with open("LatestRules.json", "r") as f:
                data = json.load(f)
                for rule in data:
                    self.rules.append(Rule(**rule))
        except FileNotFoundError:
            self.rules = []
        except Exception as e:
            print(e)
            self.rules = []
    
    def hasSameRule(self, test_rule: Rule):
        print(test_rule)
        for rule in self.rules:
            if rule.ip == test_rule.ip and rule.IPmask == test_rule.IPmask and rule.port == test_rule.port:
                return True
        return False
    
    def addRule(self, rule: Rule):
        self.rules.append(rule)
    
    def removeRule(self, rule: Rule):
        self.rules.remove(rule)
    
    def saveRules(self):
        tem_rules = []
        for rule in self.rules:
            tem_rules.append(asdict(rule))
        
        try:
            with open("LatestRules.json", "w") as f:
                json.dump(tem_rules, f)
        except Exception as e:
            print(e)
    
    def savePreviousRules(self):
        try:
            with open("LatestRules.json", "r") as f:
                previous_rules = json.load(f)
            with open("PreviousRules.json", "w") as f:
                json.dump(previous_rules, f)
        except Exception as e:
            print(e)
    
    def traverseRule(self):
        for rule in self.rules:
            print(rule.ip, rule.IPmask, rule.port, rule.limit)

ruleList = RuleList()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = MainWindowUI.Ui_MainWindow()
        self.ui.setupUi(self)
        
        self.ruleContainer = QtWidgets.QWidget()
        self.ruleLayout = QtWidgets.QVBoxLayout()
        self.ruleContainer.setLayout(self.ruleLayout)
        self.ruleLayout.addStretch()
        self.ui.scrollArea.setWidget(self.ruleContainer)
        self.ui.scrollArea.setWidgetResizable(True)
        
        self.ui.ApplyButton.clicked.connect(self.applyRules)
        self.ui.AddNewRuleButton.clicked.connect(self.openAddRuleWindow)
        self.addRuleWindow = None

        for rule in reversed(ruleList.rules):
            self.addRuleToUI(rule)

    def applyRules(self):
        # Save previous rules to PreviousRules.json and current rules to LatestRules.json
        ruleList.savePreviousRules()
        ruleList.saveRules()
        # Apply iptables rules from JSON file
        try:
            iptablesControl.load_rules_from_json("LatestRules.json")
        except Exception as e:
            # Show error message if iptables application fails
            QMessageBox.warning(self, "Error", f"Failed to apply iptables rules: {e}")
            return
        # Notify user that rules have been applied
        QMessageBox.information(self, "Information", "Rules applied")

    def openAddRuleWindow(self):
        if self.addRuleWindow is not None and self.addRuleWindow.isVisible():
            self.addRuleWindow.raise_()
            self.addRuleWindow.activateWindow()
            return
        
        self.addRuleWindow = AddRuleWindow()
        self.addRuleWindow.show()
        exec_result = self.addRuleWindow.exec_()
        if exec_result == QtWidgets.QDialog.Accepted:
            # rule = Rule(self.addRuleWindow.ip, self.addRuleWindow.IPMask, self.addRuleWindow.port, self.addRuleWindow.limit)
            rule = self.addRuleWindow.rule
            ruleList.addRule(rule)
            self.addRuleToUI(rule, position=len(ruleList.rules)-1)
        return

    def addRuleToUI(self, rule: Rule, position=0):
        # ruleWidget = RuleWidget(rule)
        ruleWidget = RuleWidget(rule, onDeleteCallback=self.deleteRuleCallback, onEditCallback=self.openEditRuleWindow)
        ruleWidget.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Fixed)
        self.ruleLayout.insertWidget(position, ruleWidget)

    def deleteRuleCallback(self, ruleWidget):
        ruleList.removeRule(ruleWidget.rule)
        ruleWidget.setParent(None)
        ruleWidget.deleteLater()

    def openEditRuleWindow(self, ruleWidget):
        """
        Open the rule editor in 'edit mode', populate fields,
        and update the existing Rule object in-place upon acceptance.
        """
        editWindow = AddRuleWindow(existing_rule=ruleWidget.rule)
        rule = ruleWidget.rule

        # 1) Populate IP and Mask
        editWindow.ui.IP.setText(rule.ip)
        editWindow.ui.Mask.setText(rule.IPmask)

        # 2) Populate Protocol
        protocol = getattr(rule, "protocol", "")
        if hasattr(editWindow.ui, "ProtocolComboBox"):
            protocols = [editWindow.ui.ProtocolComboBox.itemText(i) for i in range(editWindow.ui.ProtocolComboBox.count())]
            if protocol and protocol in protocols:
                idx = editWindow.ui.ProtocolComboBox.findText(protocol)
                editWindow.ui.ProtocolComboBox.setCurrentIndex(idx)
            else:
                editWindow.ui.ProtocolComboBox.setCurrentIndex(0)

        # 3) Populate Port
        if hasattr(editWindow.ui, "Port"):
            editWindow.ui.Port.setText(rule.port)

        # 4) Populate Limit
        if rule.limit == -1:
            editWindow.ui.checkBox.setChecked(True)
        else:
            editWindow.ui.checkBox_2.setChecked(True)
            editWindow.ui.LimitMB.setText(str(rule.limit))

        # Show dialog and update in-place if accepted
        if editWindow.exec_() == QtWidgets.QDialog.Accepted:
            updated = editWindow.rule
            orig = ruleWidget.rule
            orig.ip     = updated.ip
            orig.IPmask = updated.IPmask
            orig.port   = updated.port
            orig.limit  = updated.limit
            orig.protocol = updated.protocol

            ruleWidget.label.setText(
                ruleWidget.constructRuleStr(
                    orig.ip, orig.limit, orig.IPmask, orig.port
                )
            )

class AddRuleWindow(QDialog):
    def __init__(self, existing_rule=None):
        """
        Initialize the Add/Edit Rule dialog.
        If existing_rule is provided, enter edit mode.
        """
        super().__init__()
        self.ui = AddRuleWindowUI.Ui_Dialog()
        self.ui.setupUi(self)

        # connect signals
        self.ui.checkBox.toggled.connect(self.onCheckBoxToggled)
        self.ui.checkBox_2.toggled.connect(self.onCheckBoxToggled)
        self.ui.buttonBox.accepted.disconnect(self.accept)
        self.ui.buttonBox.accepted.connect(self.checkRuleData)
        self.ui.ProtocolComboBox.currentTextChanged.connect(self.OnProtocolSelect)
        self.ui.LimitMB.setEnabled(False)

        # editing state
        self.original_rule = existing_rule
        self.editing = existing_rule is not None

        # this will hold the new/updated Rule
        self.rule = None
    
    def onCheckBoxToggled(self):
        sender = self.sender()

        if sender == self.ui.checkBox and sender.isChecked():
            self.ui.checkBox_2.setChecked(False)
            self.ui.LimitMB.setEnabled(False)
        elif sender == self.ui.checkBox_2 and sender.isChecked():
            self.ui.checkBox.setChecked(False)
            self.ui.LimitMB.setEnabled(True)
        elif sender == self.ui.checkBox_2 and not sender.isChecked():
            self.ui.LimitMB.setEnabled(False)

    def OnProtocolSelect(self):
        protocol = self.ui.ProtocolComboBox.currentText()
        if protocol == "ALL":
            self.ui.Port.clear()
            self.ui.Port.setEnabled(False)
        elif protocol in ["TCP", "UDP"]:
            self.ui.Port.setEnabled(True)
            self.ui.Port.clear()
        elif protocol in service_to_port:
            svc = service_to_port[protocol]
            self.ui.Port.setText(str(svc[1]))
            self.ui.Port.setEnabled(False)
        else:
            self.ui.Port.setEnabled(True)
            self.ui.Port.clear()

    def checkRuleData(self):
        """
        Validate inputs, build a Rule object, and
        prevent duplicates—skipping the original when editing.
        """
        # Check IP and Port validity
        ip = self.ui.IP.text().strip()
        protocol = (
            self.ui.ProtocolComboBox.currentText().strip()
            if self.ui.ProtocolComboBox.currentText() != "ALL"
            else ""
        )
        protocol_text = self.ui.ProtocolComboBox.currentText()
        if protocol_text in ["TCP", "UDP", "ALL"]:
            port = self.ui.Port.text().strip()
        elif protocol_text in service_to_port:
            svc = service_to_port[protocol_text]
            port = str(svc[1])  
        else:
            port = self.ui.Port.text().strip()
        if len(ip) != 0 and not self.isValidIP(ip):
            QMessageBox.warning(self, "Warning", "Invalid IP")
            return
        if len(port) != 0 and not port.isdigit():
            QMessageBox.warning(self, "Warning", "Port must be an integer")
            return

        # Check IPMask validity
        IPMask = self.ui.Mask.text().strip()
        if len(IPMask) != 0 and not self.isValidMask(IPMask):
            QMessageBox.warning(self, "Warning", "Mask must be a positive integer in 0~32")
            return

        # Check limit setting
        if self.ui.checkBox.isChecked():
            limit = -1
        elif self.ui.checkBox_2.isChecked():
            limit_text = self.ui.LimitMB.text().strip()
            if not self.isNumeric(limit_text):
                QMessageBox.warning(self, "Warning", "Limit must be an positive number")
                return
            if float(limit_text) < 0:
                QMessageBox.warning(self, "Warning", "Limit must be a positive integer")
                return
            limit = float(limit_text)
        else:
            QMessageBox.warning(self, "Warning", "Please select a limit type")
            return

        # build the Rule object
        self.rule = Rule(ip, IPMask, port, limit, protocol)

        # duplicate check
        if self.editing:
            # allow same as original, but block any other duplicate
            for r in ruleList.rules:
                if (
                    r is not self.original_rule
                    and r.ip == self.rule.ip
                    and r.IPmask == self.rule.IPmask
                    and r.port == self.rule.port
                ):
                    QMessageBox.warning(self, "Warning", "Rule already exists")
                    return
        else:
            # in add mode, block any duplicate
            if ruleList.hasSameRule(self.rule):
                QMessageBox.warning(self, "Warning", "Rule already exists")
                return

        # all checks passed
        if protocol in service_to_port:
            self.rule.port = service_to_port[protocol][0]
            self.rule.port = service_to_port[protocol][1]
        self.accept()
    def isNumeric(self, value):
        if value.isdigit():
            return True
        try:
            float(value)
            return True
        except ValueError:
            return False
    
    def isValidMask(self, mask):
        if not mask.isdigit():
            return False
        elif int(mask) < 0 or int(mask) > 32:
            return False
        return True

    def isValidIP(self, ip_str):
        parts = ip_str.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit() or int(part) < 0 or int(part) > 255:
                return False
        print("checked")
        return True

class RuleWidget(QWidget):
    def __init__(self, rule: Rule, onDeleteCallback=None, onEditCallback=None):
        super().__init__()
        self.rule = rule
        self.onEditCallback   = onEditCallback
        self.onDeleteCallback = onDeleteCallback

        layout = QtWidgets.QHBoxLayout()

        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(14)

        self.label = QtWidgets.QLabel(self.constructRuleStr(rule.ip, rule.limit, rule.IPmask, rule.port))
        self.label.setFont(font)
        layout.addWidget(self.label)

        self.editButton = QtWidgets.QPushButton("Edit")
        self.editButton.setFixedHeight(25)
        self.editButton.setFixedWidth(55)
        self.editButton.setFont(font)
        layout.addWidget(self.editButton)
        self.editButton.clicked.connect(self.editSelf)

        self.deleteButton = QtWidgets.QPushButton("X")
        self.deleteButton.setStyleSheet("background-color: red; color: white;")
        self.deleteButton.setFixedHeight(25)
        self.deleteButton.setFixedWidth(30)
        self.deleteButton.setFont(font)
        layout.addWidget(self.deleteButton)

        self.setLayout(layout)

        self.setFixedHeight(40)

        self.deleteButton.clicked.connect(self.deleteSelf)

    def editSelf(self):
        if self.onEditCallback:
            self.onEditCallback(self)

    def deleteSelf(self):
        if self.onDeleteCallback:
            self.onDeleteCallback(self)

    def constructRuleStr(self, ip, limit, IPmask, port):
        IP_str = f"Rule: {ip}"
        limit_str = f" - {(str(limit) + 'MB') if limit != -1 else 'No Limit'}"
        IPmask_str = f"/{IPmask}" if len(IPmask) != 0 else ""
        port_str = f":{port}" if len(port) != 0 else ""
        return IP_str + IPmask_str + port_str + limit_str

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())