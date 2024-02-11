#   Benjamin DELPY `gentilkiwi`
#   https://blog.gentilkiwi.com / 
#   benjamin@gentilkiwi.com
#   Licence : https://creativecommons.org/licenses/by/4.0/
#
#   High Level Analyzer for STMicroelectronics ST25R3916 NFC chip on SPI bus
#   SPI settings:
#    - Significant Bit:   MSB
#    - Bits per Transfer: 8
#    - Clock State:       CPOL = 0
#    - Clock Phase:       CPHA = 1
#    - Enable Line:       Active Low

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from enum import Enum

class ST25R3916_DECODER_STATE(Enum):
    START = 0
    GET_INSTRUCTION = 1
    GET_DATA = 2
    
class ST25R3916_TYPE(Enum):
    Register_Write = 0
    Register_Read = 1
    FIFO_Load = 2
    PT_Memory_Load_A_config = 3
    PT_Memory_Load_F_config = 4
    PT_Memory_Load_TSN_data = 5
    PT_Memory_Read = 6
    FIFO_Read = 7
    Direct_Command = 8
    Unk = 9

class ST25R3916_OPERATION(Enum):
    Write = 0
    Read = 1

COMMAND_CODE = {
    0xc1: 'SET_DEFAULT',
    0xc2: 'STOP',
    0xc4: 'TRANSMIT_WITH_CRC',
    0xc5: 'TRANSMIT_WITHOUT_CRC',
    0xc6: 'TRANSMIT_REQA',
    0xc7: 'TRANSMIT_WUPA',
    0xc8: 'INITIAL_RF_COLLISION',
    0xc9: 'RESPONSE_RF_COLLISION_N',
    0xcd: 'GOTO_SENSE',
    0xce: 'GOTO_SLEEP',
    0xd0: 'MASK_RECEIVE_DATA',
    0xd1: 'UNMASK_RECEIVE_DATA',
    0xd2: 'AM_MOD_STATE_CHANGE',
    0xd3: 'MEASURE_AMPLITUDE',
    0xd5: 'RESET_RXGAIN',
    0xd6: 'ADJUST_REGULATORS',
    0xd8: 'CALIBRATE_DRIVER_TIMING',
    0xd9: 'MEASURE_PHASE',
    0xda: 'CLEAR_RSSI',
    0xdb: 'CLEAR_FIFO',
    0xdc: 'TRANSPARENT_MODE',
    0xdd: 'CALIBRATE_C_SENSOR',
    0xde: 'MEASURE_CAPACITANCE',
    0xdf: 'MEASURE_VDD',
    0xe0: 'START_GP_TIMER',
    0xe1: 'START_WUP_TIMER',
    0xe2: 'START_MASK_RECEIVE_TIMER',
    0xe3: 'START_NO_RESPONSE_TIMER',
    0xe4: 'START_PPON2_TIMER',
    0xe8: 'STOP_NRT',
    0xea: 'RC_CAL',
    0xfb: 'SPACE_B_ACCESS',
    0xfc: 'TEST_ACCESS',
}

REGISTER_ADDRESS_A = {
    0x00: 'IO_CONF1',
    0x01: 'IO_CONF2',
    0x02: 'OP_CONTROL',
    0x03: 'MODE',
    0x04: 'BIT_RATE',
    0x05: 'ISO14443A_NFC',
    0x06: 'ISO14443B_1',
    0x07: 'ISO14443B_2',
    0x08: 'PASSIVE_TARGET',
    0x09: 'STREAM_MODE',
    0x0a: 'AUX',
    0x0b: 'RX_CONF1',
    0x0c: 'RX_CONF2',
    0x0d: 'RX_CONF3',
    0x0e: 'RX_CONF4',
    0x0f: 'MASK_RX_TIMER',
    0x10: 'NO_RESPONSE_TIMER1',
    0x11: 'NO_RESPONSE_TIMER2',
    0x12: 'TIMER_EMV_CONTROL',
    0x13: 'GPT1',
    0x14: 'GPT2',
    0x15: 'PPON2',
    0x16: 'IRQ_MASK_MAIN',
    0x17: 'IRQ_MASK_TIMER_NFC',
    0x18: 'IRQ_MASK_ERROR_WUP',
    0x19: 'IRQ_MASK_TARGET',
    0x1a: 'IRQ_MAIN',
    0x1b: 'IRQ_TIMER_NFC',
    0x1c: 'IRQ_ERROR_WUP',
    0x1d: 'IRQ_TARGET',
    0x1e: 'FIFO_STATUS1',
    0x1f: 'FIFO_STATUS2',
    0x20: 'COLLISION_STATUS',
    0x21: 'PASSIVE_TARGET_STATUS',
    0x22: 'NUM_TX_BYTES1',
    0x23: 'NUM_TX_BYTES2',
    0x24: 'NFCIP1_BIT_RATE',
    0x25: 'AD_RESULT',
    0x26: 'ANT_TUNE_A',
    0x27: 'ANT_TUNE_B',
    0x28: 'TX_DRIVER',
    0x29: 'PT_MOD',
    0x2a: 'FIELD_THRESHOLD_ACTV',
    0x2b: 'FIELD_THRESHOLD_DEACTV',
    0x2c: 'REGULATOR_CONTROL',
    0x2d: 'RSSI_RESULT',
    0x2e: 'GAIN_RED_STATE',
    0x2f: 'CAP_SENSOR_CONTROL',
    0x30: 'CAP_SENSOR_RESULT',
    0x31: 'AUX_DISPLAY',
    0x32: 'WUP_TIMER_CONTROL',
    0x33: 'AMPLITUDE_MEASURE_CONF',
    0x34: 'AMPLITUDE_MEASURE_REF',
    0x35: 'AMPLITUDE_MEASURE_AA_RESULT',
    0x36: 'AMPLITUDE_MEASURE_RESULT',
    0x37: 'PHASE_MEASURE_CONF',
    0x38: 'PHASE_MEASURE_REF',
    0x39: 'PHASE_MEASURE_AA_RESULT',
    0x3a: 'PHASE_MEASURE_RESULT',
    0x3b: 'CAPACITANCE_MEASURE_CONF',
    0x3c: 'CAPACITANCE_MEASURE_REF',
    0x3d: 'CAPACITANCE_MEASURE_AA_RESULT',
    0x3e: 'CAPACITANCE_MEASURE_RESULT',
    0x3f: 'IC_IDENTITY',
    }
    
REGISTER_ADDRESS_B = {
    0x05: 'EMD_SUP_CONF',
    0x06: 'SUBC_START_TIME',
    0x0b: 'P2P_RX_CONF',
    0x0c: 'CORR_CONF1',
    0x0d: 'CORR_CONF2',
    0x0f: 'SQUELCH_TIMER',
    0x15: 'FIELD_ON_GT',
    0x28: 'AUX_MOD',
    0x29: 'TX_DRIVER_TIMING',
    0x2a: 'RES_AM_MOD',
    0x2b: 'TX_DRIVER_STATUS',
    0x2c: 'REGULATOR_RESULT',
    0x2e: 'AWS_CONF1',
    0x2f: 'AWS_CONF2',
    0x30: 'OVERSHOOT_CONF1',
    0x31: 'OVERSHOOT_CONF2',
    0x32: 'UNDERSHOOT_CONF1',
    0x33: 'UNDERSHOOT_CONF2',
    0x34: 'AWS_TIME1',
    0x35: 'AWS_TIME2',
    0x36: 'AWS_TIME3',
    0x37: 'AWS_TIME4',
    0x38: 'AWS_TIME5',
    0x39: 'AWS_TIME6',
    }

REGISTER_ADDRESS_TEST = {
    0x01: 'ANALOG_TEST_AND_OBSERVATION_1',
    0x04: '?_INCLUDING_OVERHEAT_PROTECTION',
    }

REGISTER_BANK_MAPPING = {
    'A': REGISTER_ADDRESS_A,
    'B': REGISTER_ADDRESS_B,
    'TEST': REGISTER_ADDRESS_TEST,
    }


class Hla(HighLevelAnalyzer):
    
    setting_show_registry_select = ChoicesSetting(label = 'Show B/TEST registry select', choices= ['Yes', 'No'])


    def __init__(self):

        state = ST25R3916_DECODER_STATE.START
        self.show_registry_select = (self.setting_show_registry_select == 'Yes')
        
        self.show_registry_select
        
    def decode(self, frame: AnalyzerFrame):

        if frame.type == 'enable':
            
            self.state = ST25R3916_DECODER_STATE.GET_INSTRUCTION
            self.dict = 'A'

        elif frame.type == 'result':
            
            if self.state == ST25R3916_DECODER_STATE.GET_INSTRUCTION:
            
                code = int.from_bytes(frame.data['mosi'], 'big')
            
                if (code & 0xc0) == 0xc0:

                    self.type = ST25R3916_TYPE.Direct_Command
                    
                    if(code == 0xfb):
                        self.dict = 'B'
                        toStudy = True
                    elif (code == 0xfc):
                        self.dict = 'TEST'
                        toStudy = True
                    else:
                        toStudy = False
                    
                    if(not toStudy or self.show_registry_select):
                        
                        return AnalyzerFrame(self.type.name, frame.start_time, frame.end_time, {
                            'operation': '{0:#0{1}x}'.format(code, 4) + ' - ' + COMMAND_CODE.get(code, '?')
                        })
                
                else:
                    self.state = ST25R3916_DECODER_STATE.GET_DATA
                    self.begin_frame = frame.start_time
                    self.data = ''
                    
                    if ((code & 0xc0) == 0x00): # 0 0 A5 A4 A3 A2 A1 A0
                    
                        self.type = ST25R3916_TYPE.Register_Write
                        self.operation = ST25R3916_OPERATION.Write
                        self.begin_address = code & 0x3f
                        
                    elif ((code & 0xc0) == 0x40): # 0 1 A5 A4 A3 A2 A1 A0
                    
                        self.type = ST25R3916_TYPE.Register_Read
                        self.operation = ST25R3916_OPERATION.Read
                        self.begin_address = code & 0x3f
                    
                    elif (code == 0x80): # 1 0 0 0 0 0 0 0
                        
                        self.type = ST25R3916_TYPE.FIFO_Load
                        self.operation = ST25R3916_OPERATION.Write
                        self.begin_address = 0
                    
                    elif (code == 0xa0): # 1 0 1 0 0 0 0 0
                    
                        self.type = ST25R3916_TYPE.PT_Memory_Load_A_config
                        self.operation = ST25R3916_OPERATION.Write
                        self.begin_address = 0
                        
                    elif (code == 0xa8): # 1 0 1 0 1 0 0 0
                    
                        self.type = ST25R3916_TYPE.PT_Memory_Load_F_config
                        self.operation = ST25R3916_OPERATION.Write
                        self.begin_address = 15
                        
                    elif (code == 0xac): # 1 0 1 0 1 1 0 0
                    
                        self.type = ST25R3916_TYPE.PT_Memory_Load_TSN_data
                        self.operation = ST25R3916_OPERATION.Write
                        self.begin_address = 36
                        
                    elif (code == 0xbf): # 1 0 1 1 1 1 1 1
                    
                        self.type = ST25R3916_TYPE.PT_Memory_Read
                        self.operation = ST25R3916_OPERATION.Read
                        self.begin_address = 0
                        
                    elif (code == 0x9f): # 1 0 0 1 1 1 1 1
                    
                        self.type = ST25R3916_TYPE.FIFO_Read
                        self.operation = ST25R3916_OPERATION.Read
                        self.begin_address = 0
                        
                    else:
                        self.type = ST25R3916_TYPE.Unk
            
            elif self.state == ST25R3916_DECODER_STATE.GET_DATA:            
            
                self.data += '{0:#0{1}x}'.format(int.from_bytes(frame.data['miso' if (self.operation == ST25R3916_OPERATION.Read) else 'mosi'], 'big'), 4) + ' '
                
        
        elif frame.type == 'disable':
        
            previousState = self.state
            self.state = ST25R3916_DECODER_STATE.START
            
            if previousState == ST25R3916_DECODER_STATE.GET_DATA:
                if((self.type == ST25R3916_TYPE.Register_Write) or (self.type == ST25R3916_TYPE.Register_Read)):
                    return AnalyzerFrame(self.type.name, self.begin_frame, frame.end_time, {
                        'operation': '[' + self.dict + '] {0:#0{1}x} - '.format(self.begin_address, 4) + REGISTER_BANK_MAPPING.get(self.dict).get(self.begin_address, '?'),
                        'data': self.data
                    })  
                else:
                    return AnalyzerFrame(self.type.name, self.begin_frame, frame.end_time, {
                    'data': self.data
                    }) 