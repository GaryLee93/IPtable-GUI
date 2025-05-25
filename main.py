from PyQt5.QtWidgets import QMessageBox, QMainWindow, QDialog, QWidget
from PyQt5 import QtWidgets, QtGui
from dataclasses import dataclass, asdict
import MainWindowUI, AddRuleWindowUI
import json
import sys

service_to_port = {
    "HTTP": "80",
    "HTTPS": "443",
    "SSH": "22",
    "FTP": "21",
    "SMTP": "25",
    "DNS": "53",
    "TELNET": "23",
}

@dataclass
class Rule():
    ip: str
    IPmask: str
    port: str
    limit: int

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

        for rule in ruleList.rules:
            self.addRuleToUI(rule)

    def applyRules(self):
        ruleList.savePreviousRules()
        ruleList.saveRules()
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
            self.addRuleToUI(rule)
        return

    def addRuleToUI(self, rule: Rule):
        # ruleWidget = RuleWidget(rule)
        ruleWidget = RuleWidget(rule, onDeleteCallback=self.deleteRuleCallback, onEditCallback=self.openEditRuleWindow)
        ruleWidget.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Fixed)
        self.ruleLayout.insertWidget(0, ruleWidget)

    def deleteRuleCallback(self, ruleWidget):
        ruleList.removeRule(ruleWidget.rule)
        ruleWidget.setParent(None)
        ruleWidget.deleteLater()

    def openEditRuleWindow(self, ruleWidget):
        editWindow = AddRuleWindow()
        rule = ruleWidget.rule

        # 1) Populate IP and Mask
        editWindow.ui.IP.setText(rule.ip)
        editWindow.ui.Mask.setText(rule.IPmask)

        # 2) Populate Port (built-in service or Other)
        found = False
        for svc_name, svc_port in service_to_port.items():
            if svc_port == rule.port:
                idx = editWindow.ui.PortComboBox.findText(svc_name)
                editWindow.ui.PortComboBox.setCurrentIndex(idx)
                found = True
                break
        if not found:
            idx = editWindow.ui.PortComboBox.findText("Other")
            editWindow.ui.PortComboBox.setCurrentIndex(idx)
            editWindow.ui.Port.setText(rule.port)

        # 3) Populate Limit (-1 → unlimited)
        if rule.limit == -1:
            editWindow.ui.checkBox.setChecked(True)
        else:
            editWindow.ui.checkBox_2.setChecked(True)
            editWindow.ui.LimitMB.setText(str(rule.limit))

        # Show dialog
        if editWindow.exec_() == QtWidgets.QDialog.Accepted:
            newRule = editWindow.rule

            # Update data
            ruleList.removeRule(rule)
            ruleList.addRule(newRule)

            # Update UI
            ruleWidget.rule = newRule
            ruleWidget.label.setText(
                ruleWidget.constructRuleStr(
                    newRule.ip, newRule.limit, newRule.IPmask, newRule.port
                )
            )
        
class AddRuleWindow(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = AddRuleWindowUI.Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.checkBox.toggled.connect(self.onCheckBoxToggled)
        self.ui.checkBox_2.toggled.connect(self.onCheckBoxToggled)
        self.ui.buttonBox.accepted.disconnect(self.accept)
        self.ui.buttonBox.accepted.connect(self.checkRuleData)
        self.ui.PortComboBox.currentTextChanged.connect(self.OnPortSelect)
        self.ui.LimitMB.setEnabled(False)
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

    def OnPortSelect(self):
        sender = self.sender()
        if sender == self.ui.PortComboBox and sender.currentText() == "Other":
            self.ui.Port.setEnabled(True)
        else:
            self.ui.Port.setEnabled(False)

    def checkRuleData(self):
        #Check IP and Port
        ip = self.ui.IP.text().strip()
        port = self.ui.Port.text().strip() if self.ui.PortComboBox.currentText() == "Other" else service_to_port[self.ui.PortComboBox.currentText()] 
        if len(port) == 0 and len(ip) == 0:
            QMessageBox.warning(self, "Warning", "At least port or IP must be filled")
            return 
        if len(ip) != 0 and not self.isValidIP(ip):
            QMessageBox.warning(self, "Warning", "Invalid IP")
            return 
        if len(port) != 0 and (not port.isdigit()):
            QMessageBox.warning(self, "Warning", "Port must be a Integer")
            return 
        
        #Check IPMask
        IPMask = self.ui.Mask.text().strip()
        if len(IPMask) != 0 and not self.isValidMask(IPMask):
            QMessageBox.warning(self, "Warning", "Mask must be a positive integer in 0~32")
            return 

        #Check limit
        if self.ui.checkBox.isChecked():
            limit = -1
        elif self.ui.checkBox_2.isChecked():
            limit = self.ui.LimitMB.text().strip()
            if not limit.isdigit():
                QMessageBox.warning(self, "Warning", "Limit must be a integer")
                return 
            elif int(limit) < 0:
                QMessageBox.warning(self, "Warning", "Limit must be a positive integer")
                return 
            else:
                limit = int(limit)
        else:
            QMessageBox.warning(self, "Warning", "Please select a limit type")  
            return
        
        self.rule = Rule(ip, IPMask, port, limit)        
        if(ruleList.hasSameRule(self.rule)):
            QMessageBox.warning(self, "Warning", "Rule already exists")
            return 
        self.accept()
    
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
        # ruleList.removeRule(self.rule)
        # self.setParent(None)
        # self.deleteLater()

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
