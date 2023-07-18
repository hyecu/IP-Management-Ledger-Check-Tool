from PyQt5.QtGui import QIcon, QFont, QDesktopServices
from PyQt5.QtCore import QUrl, QThread, pyqtSignal, Qt
from openpyxl import Workbook
from openpyxl.styles import Border, Side, PatternFill, NamedStyle, Alignment, Font
from openpyxl.utils.dataframe import dataframe_to_rows
from PyQt5.QtWidgets import *
from queue import Queue
import threading
import psutil
import sys
import socket
import ipaddress
import subprocess
import re
import pandas as pd
import os
import time

class progress(QThread):
    update_progress = pyqtSignal(int)
    
    def run(self):
        total = 100
        for i in range(total + 1):
            # 작업 수행
            time.sleep(0.1)

            # 진행률 업데이트
            self.update_progress.emit(i)

        # 작업 완료 후 시그널 발생
        self.finished.emit()

# 전처리 (엑셀 기준으로 데이터가 존재하는 행과 열부터 시작하도록 DataFrame 자르기)
def preprocessing(data):
    data = data[data.apply(lambda row: any(row.notna()), axis=1)]
    if 'Unnamed' in data.columns[0]:
        data = data.rename(columns=data.iloc[0])
    data = data.dropna(axis='columns', how='all')
    data = data[1:]
    data.columns = [str(i) if pd.isna(col) else col for i, col in enumerate(data.columns, 1)]
    return data

# IP 주소 컬럼이름
def get_ip_columns(data, pattern):
    ip_columns = [column for column in data.columns if data[column].apply(lambda x: isinstance(x, str) and re.match(pattern, x)).any()]
    return ip_columns

# 호스트 컬럼이름
def get_host_column(data):
    for column in data.columns:
        if 'host' in column.lower() or '호스트' in column:
            host_column = column
            break
    return host_column

# 정상 IP 주소 필터링 + (비정상 IP 주소는 unnormal_ip_L에 추가, 리턴 안해도 반영됨)
def filtering_ip(data, pattern, ip_columns, unnormal_ip_L):
    dropped_data = data.copy()
    dropped_data.dropna(subset=[ip_columns[0]], inplace=True)
    all_ip_excel_L = dropped_data[ip_columns[0]].astype(str).to_list()
    normal_ip_DF = pd.DataFrame(columns=data.columns)

    for ip in all_ip_excel_L:
        if re.match(pattern, ip):
            normal_ip_DF = pd.concat([normal_ip_DF, data.loc[(data[ip_columns] == ip).all(axis=1), :]], ignore_index=True)
        else:
            unnormal_ip_L.append(ip)
    
    return normal_ip_DF

# 관리대장 IP, 스캔IP 비교 결과 분류(3가지 경우의 수)
def classification_data(excel_dict, unnormal_ip_L, scan_result, ip_columns, result):

    try:
        excel_ip_L = list(excel_dict.keys())
        scan_ip_L = list(scan_result.keys())
        excel_set = set(excel_ip_L)
        scan_set = set(scan_ip_L)

        matching_ip = excel_set.intersection(scan_set)
        missing_from_scan = excel_set - matching_ip
        missing_from_excel = scan_set - matching_ip

        matching_ip = list(matching_ip)
        missing_from_scan = list(missing_from_scan)
        missing_from_excel = list(missing_from_excel)
        
        chk_null_ip = result[ip_columns[0]].isna().sum()
        
        if matching_ip:
            result = process_matching_data(matching_ip, excel_dict, scan_result, ip_columns, result)
        if missing_from_scan:
            result = process_missing_scan(missing_from_scan, excel_dict, ip_columns, result)
        if missing_from_excel:
            result = process_missing_excel(missing_from_excel, ip_columns, scan_result, result)
        if unnormal_ip_L:
            result = process_unnormal_ip(unnormal_ip_L, ip_columns, result)
        if chk_null_ip:
            result = process_null_ip(result, ip_columns)
    except:
        return 
    else:
        return result

# 대장o, 스캔o
def process_matching_data(matching_ip, excel_dict, scan_result, ip_columns, result):
    # 관리대장: ip랑 host 딕셔너리로 결합
    # ip만 따로 추출해서 3가지 경우로 분류
    # 일치하면? ip에 해당하는 딕셔너리(host)랑 스캔ip에 해당하는 딕셔너리(host) 비교
    for ip in matching_ip:
        excel_host = excel_dict[ip]
        scan_host = scan_result[ip]

        if excel_host != scan_host:
            result.loc[result[ip_columns[0]] == ip, 'result'] = '호스트 불일치'
    return result

# 대장o, 스캔x
def process_missing_scan(missing_from_scan, excel_dict, ip_columns, result):
    #대장에만 있는 ip를 주면 ↓출력
    #"대장o 스캔x
    # host: 대장host이름"
    for ip in missing_from_scan:
        excel_host = excel_dict[ip]
        result.loc[result[ip_columns[0]] == ip, 'result'] = f"대장o, 스캔x  (host: {excel_host})"
    return result

# 대장x, 스캔o (IP 검증 결과를 저장할 DataFrame 및 컬럼 만들기)
def process_missing_excel(missing_from_excel, ip_columns, scan_result, result):
    # 대장에 없는 IP 처리하기
    if missing_from_excel:
        # 기존 관리대장에 새로 추가
        new_rows = pd.DataFrame(columns=result.columns)
        new_rows[ip_columns[0]] = missing_from_excel
        new_rows['result'] = new_rows[ip_columns[0]].map(scan_result).apply(lambda x: f'대장x 스캔o  (host: {x})' if x is not None else '대장x 스캔o  (host: nan)')
        result = pd.concat([result, new_rows], ignore_index=True)  #병합
    return result

# IP 주소 오류
def process_unnormal_ip(unnormal_ip_L, ip_columns, result):
    for unnormal_ip in unnormal_ip_L:
        result.loc[result[ip_columns[0]].astype(str) == str(unnormal_ip), 'result'] = 'Invalid IP Address, 스캔불가'
    return result

# IP 주소가 존재하지 않음
def process_null_ip(result, ip_columns):
    result.loc[result[ip_columns[0]].isna(), 'result'] = 'No IP Address, 스캔불가'
    return result

# 검증 수행
def Verification(file, scan_result, output_file):
    try:
        # IP 관리대장 파일 불러오기
        data = pd.read_excel(file)
        # 전처리 (엑셀 기준으로 데이터가 존재하는 행과 열부터 시작하도록 DataFrame 자르기)
        data = preprocessing(data)
        # IP 주소 정규표현식
        pattern = r'^(?!255\.255\.255\.(?:128|192|224|240|248|252|255)$)(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?!0)([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
        # 결과 저장할 DataFrame
        result = data.copy()
        result['result'] = ''
        # IP 컬럼 가져오기
        ip_columns = get_ip_columns(data, pattern)
        # 정상 IP 주소 값만 필터링 + (비정상 IP 주소 저장할 배열 만들기)
        unnormal_ip_L = []
        normal_ip_DF = filtering_ip(data, pattern, ip_columns, unnormal_ip_L)
        
        # 호스트 컬럼 가져오기
        host_column = get_host_column(data)

        #관리대장 ip(key), host(value) 딕셔너리
        excel_dict = dict(zip(normal_ip_DF[ip_columns[0]], normal_ip_DF[host_column]))
        
        # 대장 처리 및 스캔 결과 처리
        result = classification_data(excel_dict, unnormal_ip_L, scan_result, ip_columns, result)

        # 결과 저장
        save_to_excel(result, ip_columns, host_column, output_file)
    except Exception as error:
        print(error)
        return False
    else:
        return True


# 엑셀 출력
def save_to_excel(result, ip_column, host_column, output_file):
    # 결과 엑셀 파일(.xlsx)로 출력하기
    workbook = Workbook()
    worksheet = workbook.active

    # 데이터프레임을 엑셀에 저장
    for r in dataframe_to_rows(result, index=False, header=True):
        worksheet.append(r)

    # 데이터 있는 곳에 모든 테두리 적용
    apply_borders(worksheet, start_row=1, start_col=1, end_row=worksheet.max_row, end_col=worksheet.max_column)
    
    for row in worksheet.iter_rows(min_row=2, max_row=worksheet.max_row, min_col=1, max_col=worksheet.max_column):
        for cell in row:
            if cell.column == result.columns.get_loc('result') + 1:
                if '대장x' in cell.value:
                    # 대장x인 행에 대해서만 빨간색 적용
                    for column in worksheet.iter_cols(min_row=cell.row, max_row=cell.row, min_col=1, max_col=worksheet.max_column):
                        for cell in column:
                            apply_color(worksheet, row=cell.row, column=cell.column, color='F6CECE')

                    # result 컬럼에 색상 적용 (더 진한 빨간색)
                    apply_color(worksheet, row=cell.row, column=cell.column, color='FF0000')

                    # IP 주소 컬럼에 색상 적용 (더 진한 빨간색)
                    ip_column_index = result.columns.get_loc(ip_column[0]) + 1
                    apply_color(worksheet, row=cell.row, column=ip_column_index, color='FF0000')
                    
                elif '스캔x' in cell.value:
                    # 스캔x인 행에 대해서만 노란색 적용
                    for column in worksheet.iter_cols(min_row=cell.row, max_row=cell.row, min_col=1, max_col=worksheet.max_column):
                        for cell in column:
                            apply_color(worksheet, row=cell.row, column=cell.column, color='F6F5CC')

                    # result 컬럼에 색상 적용 (더 진한 노란색)
                    apply_color(worksheet, row=cell.row, column=cell.column, color='FFFF00')

                    # 호스트 컬럼에 색상 적용 (더 진한 노란색)
                    ip_column_index = result.columns.get_loc(host_column) + 1
                    apply_color(worksheet, row=cell.row, column=ip_column_index, color='FFFF00')

                    # IP 주소 컬럼에 색상 적용 (더 진한 노란색)
                    ip_column_index = result.columns.get_loc(ip_column[0]) + 1
                    apply_color(worksheet, row=cell.row, column=ip_column_index, color='FFFF00')
                    
                elif '호스트 불일치' == cell.value:
                    # '호스트 불일치' 행에 대해서만 색상 적용(실버블론드)
                    for column in worksheet.iter_cols(min_row=cell.row, max_row=cell.row, min_col=1, max_col=worksheet.max_column):
                        for cell in column:
                            apply_color(worksheet, row=cell.row, column=cell.column, color='FFFFCC')

                    # result 컬럼에 색상 적용 (카키)
                    apply_color(worksheet, row=cell.row, column=cell.column, color='CC9933')

                    # 호스트 컬럼에 색상 적용 (카키)
                    ip_column_index = result.columns.get_loc(host_column) + 1
                    apply_color(worksheet, row=cell.row, column=ip_column_index, color='CC9933')
                    
                    # IP 주소 컬럼에 색상 적용 (카키)
                    ip_column_index = result.columns.get_loc(ip_column[0]) + 1
                    apply_color(worksheet, row=cell.row, column=ip_column_index, color='CC9933')
                
                elif 'No IP Address' in cell.value:
                    # 'No IP Address' 행에 대해서만 분홍색 적용
                    for column in worksheet.iter_cols(min_row=cell.row, max_row=cell.row, min_col=1, max_col=worksheet.max_column):
                        for cell in column:
                            apply_color(worksheet, row=cell.row, column=cell.column, color='F6D8CE')

                    # result 컬럼에 색상 적용 (더 진한 분홍색)
                    apply_color(worksheet, row=cell.row, column=cell.column, color='FF8888')

                    # IP 주소 컬럼에 색상 적용 (더 진한 분홍색)
                    ip_column_index = result.columns.get_loc(ip_column[0]) + 1
                    apply_color(worksheet, row=cell.row, column=ip_column_index, color='FF8888')
                    
                    
                elif 'Invalid IP Address' in cell.value:
                    # 'Invalid IP Address' 행에 대해서만 주황색 적용
                    for column in worksheet.iter_cols(min_row=cell.row, max_row=cell.row, min_col=1, max_col=worksheet.max_column):
                        for cell in column:
                            apply_color(worksheet, row=cell.row, column=cell.column, color='ECCDB0')

                    # result 컬럼에 색상 적용 (더 진한 주황색)
                    apply_color(worksheet, row=cell.row, column=cell.column, color='E26B0A')

                    # IP 주소 컬럼에 색상 적용 (더 진한 주황색)
                    ip_column_index = result.columns.get_loc(ip_column[0]) + 1
                    apply_color(worksheet, row=cell.row, column=ip_column_index, color='E26B0A')
                
                else:
                    next

    # 컬럼 스타일 정의
    style = NamedStyle(name='Header')
    style.alignment = Alignment(horizontal='center', vertical='center')
    style.font = Font(name='맑은 고딕', bold=True)
    # 컬럼 스타일 적용
    for cell in worksheet[1]:
        cell.style = style
        apply_color(worksheet, row=cell.row, column=cell.column, color='D3D3D3')  # 연회색 적용

    apply_borders(worksheet, start_row=1, start_col=1, end_row=worksheet.max_row, end_col=worksheet.max_column)

    # 열의 너비 자동 조절
    for column in worksheet.columns:
        max_length = 0
        column = [cell for cell in column]
        # 최대 길이 계산
        for cell in column:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(cell.value)
            except:
                pass
        adjusted_width = (max_length + 2) * 1.2  # 글자 수에 따라 조절할 너비 계산
        worksheet.column_dimensions[cell.column_letter].width = adjusted_width

    # 셀 정렬 (가운데 정렬)
    for row in worksheet.iter_rows(min_row=1, max_row=worksheet.max_row, min_col=1, max_col=worksheet.max_column):
        for cell in row:
            cell.alignment = Alignment(horizontal='center', vertical='center')

    # 파일 저장
    workbook.save(output_file)
    # print("결과를 저장한 파일:", output_file)

def apply_borders(worksheet, start_row, start_col, end_row, end_col):
    border_style = Side(border_style="thin", color="000000")
    border = Border(top=border_style, right=border_style, bottom=border_style, left=border_style)

    for row in range(start_row, end_row + 1):
        for col in range(start_col, end_col + 1):
            cell = worksheet.cell(row=row, column=col)
            cell.border = border

def apply_color(worksheet, row, column, color):
    cell = worksheet.cell(row=row, column=column)
    cell.fill = PatternFill(start_color=color, end_color=color, fill_type="solid")


def get_all_ip_addresses(cidr):        #cidr 형식을 배열로 푸는 과정 192.168.0.1/24 -> [192.168.0.1, 192.168.0.2 ... 192.168.0.254]
    ip_network = ipaddress.ip_network(cidr)
    all_ip_addresses = [str(ip) for ip in ip_network.hosts()]
    return all_ip_addresses

def get_network_cidr(interface):  #네트워크 정보 가져오기 ip,서브넷 등등등..
    addresses = psutil.net_if_addrs()
    if interface in addresses:
        for addr in addresses[interface]:
            if addr.family == socket.AF_INET:
                return ipaddress.ip_interface((addr.address, addr.netmask)).network
    return None

def GetHostByAddress(ip_address):  #호스트네임 검색
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        return "Unknown"

def worker(queue, results):
    while True:
        ip = queue.get()
        if ip is None:
            break
        cmd = f'powershell.exe Test-Connection -ComputerName {ip} -Count 2 -Quiet'
        result = subprocess.run(["powershell.exe", "-Command", cmd], capture_output=True, text=True, shell=True)
        if result.stdout.strip() == 'True':
            hostname = GetHostByAddress(ip)
            results[ip] = hostname
        queue.task_done()

def get_network_cidr_mapping():
    interfaces = psutil.net_if_stats().keys()
    mapping = {}
    for interface in interfaces:
        cidr = get_network_cidr(interface)
        if cidr is not None:
            mapping[interface] = str(cidr)
    return mapping

def test_connection(text):
    try:
        text = text.split(":")
        cidr_ipadress = text[1].strip()
        ip_addresses = get_all_ip_addresses(cidr_ipadress)
        num_threads = 20

        queue = Queue()
        results = {}
        threads = []
        ip_and_hostname = {}
        for _ in range(num_threads):
            t = threading.Thread(target=worker, args=(queue, results))
            t.start()
            threads.append(t)

        for ip in ip_addresses:
            queue.put(ip)

        queue.join()

        for _ in range(num_threads):
            queue.put(None)
        for t in threads:
            t.join()

        for ip, hostname in results.items():
            ip_and_hostname[ip] = hostname
    except:
        return False
    else:
        return ip_and_hostname


class MyWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowIcon(QIcon(''))
        self.setWindowTitle('IP 관리대장 점검 시스템')
        self.resize(800, 400)
        self.center()
                
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setGeometry(70,305,560,40)

        self.progress_bar.setStyleSheet("border: 5px solid; background-color: white")

        
        
        self.font = QLabel('@Copyrights by TMI Potato',self)
        self.font.setGeometry(595,355,230,50)
        font = self.font.font()
        font.setPointSize(6)
        font.setWeight(QFont.Bold)
        self.font.setFont(font)
        

        menubar = self.menuBar()
        menu = menubar.addMenu('도움말')
        help = QAction('도움말 보기', self)
        help.triggered.connect(self.help_load)
        help.setShortcut('Ctrl+h')
        menu.addAction(help)  



        self.pushButton = QPushButton('△불러오기', self)
        self.pushButton.clicked.connect(self.pushButtonClicked)
        self.pushButton.setGeometry(640, 50, 130, 70)   
        self.pushButton.setFont(QFont('나눔고딕',10))
        
        self.savebutton = QPushButton('▽저장 위치', self)
        self.savebutton.clicked.connect(self.saveFileDialog)
        self.savebutton.setGeometry(640, 125, 130, 70)
        self.savebutton.setFont(QFont('나눔고딕',10))
        
        self.scanbutton = QPushButton('SCAN', self)
        self.scanbutton.setShortcut("s") #단축키 
        self.scanbutton.setGeometry(640, 205, 130, 140)
        self.scanbutton.setFont(QFont('나눔고딕',10))
        self.scanbutton.clicked.connect(self.scanbuttonClicked)
        
        self.cb = QComboBox(self)
        for interface, cidr in get_network_cidr_mapping().items():
            self.cb.addItem(f" {interface}: {cidr}")
        self.cb.setGeometry(70, 205, 560, 70)
        self.cb.setFont(QFont('나눔고딕',10))

        self.push_line_edit = QLineEdit(self)
        self.push_line_edit.setReadOnly(True)
        self.push_line_edit.setGeometry(70, 50, 560, 70)
        self.push_line_edit.setFont(QFont('나눔고딕',10))

        self.save_line_edit = QLineEdit(self)
        self.save_line_edit.setGeometry(70, 125, 560,70)
        self.save_line_edit.setFont(QFont('나눔고딕',10))
        
        self.pushButton.setStyleSheet("border: 5px solid; background-color: white")
        self.savebutton.setStyleSheet("border: 5px solid; background-color: white")
        self.scanbutton.setStyleSheet("border: 5px solid; background-color: white")
        self.cb.setStyleSheet("border: 5px solid; background-color: white")
        self.push_line_edit.setStyleSheet("border: 5px solid;")
        self.save_line_edit.setStyleSheet("border: 5px solid;")

    def help_load(self):
        url = QUrl('https://github.com/Phqasue/Potato-IP-Scanner')
        QDesktopServices.openUrl(url)
        
    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()

        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def pushButtonClicked(self):
        fname = QFileDialog.getOpenFileName(self)
        self.push_line_edit.setText(fname[0])

    def saveFileDialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog

        selected_dir = QFileDialog.getExistingDirectory(self, '저장 폴더 선택', options=options)
        self.save_line_edit.setText(selected_dir)

    def scanbuttonClicked(self):
        push_file = self.push_line_edit.text()
        save_text = self.save_line_edit.text()
        
        if push_file == '':
            QMessageBox.warning(self, '경고', 'IP 관리 대장을 불러와주세요.')
            return
        elif os.path.splitext(push_file)[1] != '.xlsx':
            QMessageBox.warning(self, '경고', '올바르지 않은 파일 형식입니다.')
            return
        elif save_text == '':
            QMessageBox.warning(self, '경고', '저장 위치를 선택해주세요.')
            return
        if not os.path.exists(push_file):
            QMessageBox.warning(self, '경고', '불러온 파일이 존재하지 않습니다.')
            return
        
        QMessageBox.information(self, '알림', '스캔이 정상적으로 시작이 되었습니다.')
        self.scanbutton.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("%p%")  # 진행 상황 표시 형식 설정
        self.progress_bar.setAlignment(Qt.AlignCenter)  # 진행 상황 텍스트 가운데 정렬
        self.thread = progress()
        self.thread.update_progress.connect(self.update_progress_bar)
        self.thread.finished.connect(self.progress_finished)
        self.thread.start()

        ipaddress = self.cb.currentText()
        file_name_without_ext, file_ext = os.path.splitext(os.path.basename(push_file))
        new_file_name = file_name_without_ext + "_Result" + file_ext
        new_file_dir = save_text + '/' + new_file_name
        scan_result = test_connection(ipaddress)

        if scan_result == False:
            QMessageBox.information(self, '알림', '스캔중 오류가 발생했습니다.\n 네트워크 대역을 다시 확인해주세요.')
            return
        else:
            next
        
        if Verification(push_file, scan_result, new_file_dir):
            QMessageBox.information(self, '알림', '비교파일이 정상적으로 생성되었습니다.')
            return
        else:
            QMessageBox.information(self, '알림', '파일 비교중 오류가 발생했습니다.')
            return
        
    def update_progress_bar(self,value):
        self.progress_bar.setValue(value)
        
    def progress_finished(self):
        self.scanbutton.setEnabled(True)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MyWindow()
    window.show()
    app.exec_()
