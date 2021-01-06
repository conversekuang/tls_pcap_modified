#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author: converse
@version: 1.0.0
@file: PraseTLS.py.py
@time: 2020/12/25 16:40
"""
# PraseTLS.py
import struct
import dpkt
from parse_tls.constants import PRETTY_NAMES
from binascii import hexlify
from asn1crypto import x509


def parse_tcp_packet(tcp):
    """
    Parses TCP packet
    :param tcp:
    :return:
    """
    # stream={}
    # 20 Change Cipher Spec
    # 21 alert
    # 22 handshake
    if len(tcp.data) > 0:
        if tcp.data[0] in set((20, 21, 22, 23)):
            stream = tcp.data
            res_list = parse_tls_records(stream)
            return res_list
        else:
            return [[["TCP", len(tcp.data)]]]


def parse_tls_records(stream):
    """
    Parse TLS Records
    :param stream:
    :return: [类型,长度],是一维数组，一个record是有多个类型，所以二维数组。records是三维数组。
    """
    tcp_payload_list = []

    try:
        records, bytes_used = dpkt.ssl.tls_multi_factory(stream)
    except dpkt.ssl.SSL3Exception as exception:
        return ''
    # print("bytes_used", bytes_used)
    # 可以识别出来的record
    for record in records:
        record_type = pretty_name('tls_record', record.type)
        if record_type == 'handshake':
            handshake = []
            # print("\nContent Type, 1, {}".format(pretty_name('tls_record', record.type)))
            # print("Version, 2, {}".format(pretty_name('tls_version', record.version)))
            # print("Length, 2, {}".format(record.length))
            handshake.append(["Content Type", 1])
            handshake.append(["Version", 2])
            handshake.append(["Length", 2])
            if ord(record.data[:1]) not in (1, 2):
                # Encrypted Handshake Message 直接就不需要在分析了
                handshake.append(["Encrypted Handshake Message", len(record.data)])
                res_list = handshake
            else:
                res_list = parse_tls_handshake(record.data, handshake)

            # 加前缀
            handshake_type = ord(record.data[:1])
            revise_name_list = []
            if handshake_type == 1:
                for element in res_list:
                    revise_name_list.append(["client " + element[0], element[1]])
            if handshake_type == 2:
                for element in res_list:
                    revise_name_list.append(["server " + element[0], element[1]])

            # TODO Handshake message 不属于client hello or server hello 20200105
            if handshake_type not in (1, 2):
                revise_name_list = res_list
            tcp_payload_list.append(revise_name_list)

        if record_type == 'change_cipher':
            change_cipher = []
            # print("\nContent Type, 1, {}".format(pretty_name('tls_record', record.type)))
            # print("Version, 2, {}".format(pretty_name('tls_version', record.version)))
            # print("Length, 2, {}".format(record.length))
            # print("Change Cipher Spec Message", len(record.data), record.data)
            change_cipher.append(["Content Type", 1])
            change_cipher.append(["Version", 2])
            change_cipher.append(["Length", 2])
            change_cipher.append(["Change Cipher Spec Message", len(record.data)])
            tcp_payload_list.append(change_cipher)

        if record_type == 'application_data':
            application_data = []
            # print("\nContent Type, 1, {}".format(pretty_name('tls_record', record.type)))
            # print("Version, 2, {}".format(pretty_name('tls_version', record.version)))
            # print("Length, 2, {}".format(record.length))
            # print("Encrypted Application Data", len(record.data), record.data)
            application_data.append(["Content Type", 1])
            application_data.append(["Version", 2])
            application_data.append(["Length", 2])
            application_data.append(["Encrypted Application Data", len(record.data)])
            tcp_payload_list.append(application_data)

    # 没有record，因为是一部分加密信息，针对的PDU那种。因为一整包都是PDU
    if len(records) == 0 and stream[0] == 23:
        # print("Encrypted Application Data", len(stream), stream)
        tcp_payload_list.append([["TCP segment Data", len(stream)]])

    # 有读出来有record但是没有读取完，剩下的是segment。如果消耗的字节和payload大小不一致，一包里面一部分是PDU
    if len(records) > 0 and len(stream) - bytes_used > 0:
        tcp_payload_list.append([["TCP segment Data", len(stream) - bytes_used]])

    if len(records) == 0 and bytes_used == 0:
        tcp_payload_list.append([["TCP segment Data", len(stream)]])

    return tcp_payload_list


def parse_tls_handshake(data, tcp_payload_list):
    """
    Parses TLS Handshake message contained in data according to their type.
    """
    try:
        handshake_type = ord(data[:1])
        if handshake_type == 4:
            # print('[#] New Session Ticket is not implemented yet')
            return ''
        else:
            handshake = dpkt.ssl.TLSHandshake(data)
    except dpkt.ssl.SSL3Exception as exception:
        return ''
    except dpkt.dpkt.NeedData as exception:
        return ''

    # print("HandShake Type, 1, {}".format(pretty_name('handshake_type', handshake.type)))
    # print("HandShake Length, {}, {}\n".format(len(handshake.length_bytes), handshake.length))
    tcp_payload_list.append(["HandShake Type", 1])
    tcp_payload_list.append(["HandShake Length", len(handshake.length_bytes)])

    if handshake.type == 1:
        # 1  Client Hello   2  Server Hello  3 Certificate
        res_list = parse_client_hello(handshake, tcp_payload_list)
        return res_list
    if handshake.type == 2:
        res_list = parse_server_hello(handshake, tcp_payload_list)
        return res_list
    if handshake.type == 11:
        res_list = parse_certificate(handshake, tcp_payload_list)
    else:
        return ''


def parse_client_hello(handshake, tcp_payload_list):
    # compressions = []
    # cipher_suites = []
    # extensions = []
    # print("Version, 2,{}".format(pretty_name("tls_version", handshake.data.version)))
    # print("Random,{}, {}".format(len(handshake.data.random), handshake.data.random))
    # print("Session ID Length, 1,{}".format(len(handshake.data.session_id)))
    # print("Session ID, {}, {}".format(len(handshake.data.session_id), handshake.data.session_id))
    # print("Cipher Suites Length, 2, {}".format(handshake.data.num_ciphersuites * 2))

    tcp_payload_list.append(["Version", 2])
    tcp_payload_list.append(["Random", len(handshake.data.random)])
    tcp_payload_list.append(["Session ID Length", 1])
    tcp_payload_list.append(["Session ID", len(handshake.data.session_id)])
    tcp_payload_list.append(["Cipher Suites Length", 2])

    payload = handshake.data.data
    session_id, payload = unpacker('p', payload)
    cipher_suites, pretty_cipher_suites = parse_extension(payload, 'cipher_suites')
    # print('Cipher Suites', len(cipher_suites) * 2, pretty_cipher_suites)

    tcp_payload_list.append(['Cipher Suites', len(cipher_suites) * 2])

    # TODO 如果要打印Cipher Suites， 循环加入这个tcp_payload_list， 长度，name
    # for i in range(0, len(cipher_suites)):
    #     tcp_payload_list.append(['Cipher Suites' + pretty_cipher_suites[i], 2])

    # consume 2 bytes for each cipher suite plus 2 length bytes
    # cipher_suites 遍历了
    payload = payload[(len(cipher_suites) * 2) + 2:]
    compressions, pretty_compressions = parse_extension(payload, 'compression_methods')
    # print("Compression Methods Length, 1, {}".format(len(compressions)))
    # print('Compression Methods', 1, pretty_compressions)

    tcp_payload_list.append(["Compression Methods Length", 1])
    tcp_payload_list.append(["Compression Methods", 1])

    payload = payload[len(compressions) + 1:]

    # print('Extensions length', 2, payload[:2])

    tcp_payload_list.append(["Extensions length", 2])

    payload = payload[2:]
    # print('#########  Extensions  ########', len(payload))
    # consume 1 byte for each compression method plus 1 length byte

    for extension in handshake.data.extensions:
        # print("{}, {}".format(pretty_name("extension_type", extension[0]), len(extension[1]) + 4))
        tcp_payload_list.append([pretty_name("extension_type", extension[0]), len(extension[1]) + 4])

    # 解析详细的
    # str1 = parse_extensions(payload)
    # print(str1)
    return tcp_payload_list


def parse_server_hello(handshake, tcp_payload_list):
    """
    Parses server hello handshake.
    """
    # print("Version, 2,{}".format(pretty_name("tls_version", handshake.data.version)))
    # print("Random,{}, {}".format(len(handshake.data.random), handshake.data.random))
    # print("Session ID Length, 1,{}".format(len(handshake.data.session_id)))
    # print("Session ID, {}, {}".format(len(handshake.data.session_id), handshake.data.session_id))

    tcp_payload_list.append(["Version", 2])
    tcp_payload_list.append(["Random", len(handshake.data.random)])
    tcp_payload_list.append(["Session ID Length", 1])
    tcp_payload_list.append(["Session ID", len(handshake.data.session_id)])

    session_id, payload = unpacker('p', handshake.data.data)

    cipher_suite, payload = unpacker('H', payload)
    # print('Cipher Suite', 2, pretty_name('cipher_suites', cipher_suite))
    tcp_payload_list.append(["Cipher Suite", 2])

    compression, payload = unpacker('B', payload)
    # print('Compression Methods', 1, pretty_name('compression_methods', compression))
    tcp_payload_list.append(['Compression Methods', 1])

    # 为了避免server hello没有 extensions
    without_extensions_length = 2 + len(handshake.data.random) + 1 + len(handshake.data.session_id) + 2 + 1
    #  Version Random Session_ID_Length Session_ID Cipher_Suite Compression_Methods
    if len(handshake.data) > without_extensions_length:
        # print('Extensions length', 2, payload[:2])
        tcp_payload_list.append(['Extensions length', 2])
        # extensions = parse_extensions(payload)
        for extension in handshake.data.extensions:
            # print(pretty_name("extension_type", extension[0]), len(extension[1]) + 4, extension[1])
            tcp_payload_list.append([pretty_name("extension_type", extension[0]), len(extension[1]) + 4])
    return tcp_payload_list


def parse_certificate(handshake, tcp_payload_list):
    hd_data = handshake.data
    assert isinstance(hd_data, dpkt.ssl.TLSCertificate)
    certs = []
    # print(dir(hd))
    for i in range(len(hd_data.certificates)):
        # print("hd.certificates[i]:", hd_data.certificates[i])
        try:
            cert = x509.Certificate.load(hd_data.certificates[i])
            sha = cert.sha256_fingerprint.replace(" ", "")
            # print(sha)
            certs.append(sha)
        except Exception as e:
            print(e)
    tcp_payload_list.append(["certificate", sum([len(i) for i in certs])])
    return tcp_payload_list


def parse_extensions(payload):
    """
    Parse data as one or more TLS extensions.
    """
    extensions = []
    serverName = ''
    if len(payload) <= 0:
        return ''
    extensions_len, payload = unpacker('H', payload)
    while len(payload) > 0:
        extension = Extension(payload)
        print(extension._type_name, extension._length, extension._pretty_data)

        extensions.append(extension)
        # serverName = extension.PrintSeverName()
        # if len(serverName):
        #     print(serverName)
            # break
        # consume 2 bytes for type and 2 bytes for length
        payload = payload[extension._length + 4:]

    return serverName


class Extension(object):
    """
    Encapsulates TLS extensions.
    """

    def __init__(self, payload):
        self._type_id, payload = unpacker('H', payload)
        self._type_name = pretty_name('extension_type', self._type_id)
        self._length, payload = unpacker('H', payload)
        # Data contains an array with the 'raw' contents
        self._data = None
        # pretty_data contains an array with the 'beautified' contents
        self._pretty_data = None
        if self._length > 0:
            self._data, self._pretty_data = parse_extension(payload[:self._length],
                                                            self._type_name)

    def PrintSeverName(self):
        # Prints out data array in textual format
        if self._type_name == 'server_name':
            return self._pretty_data[0][2:-1]
        # return '{0}: {1}'.format(self._type_name, self._pretty_data)
        return ''


def parse_extension(payload, type_name):
    """
    Parses an extension based on the type_name.
    Returns an array of raw values as well as an array of prettified values.
    """
    entries = []
    pretty_entries = []
    format_list_length = 'H'
    format_entry = 'B'
    list_length = 0
    if type_name == 'elliptic_curves':
        format_list_length = 'H'
        format_entry = 'H'
    if type_name == 'ec_point_formats':
        format_list_length = 'B'
    if type_name == 'compression_methods':
        format_list_length = 'B'
        format_entry = 'B'
    if type_name == 'heartbeat':
        format_list_length = 'B'
        format_entry = 'B'
    if type_name == 'next_protocol_negotiation':
        format_entry = 'p'
    else:
        if len(payload) > 1:  # contents are a list
            list_length, payload = unpacker(format_list_length, payload)
    if type_name == 'status_request' or type_name == 'status_request_v2':
        _type, payload = unpacker('B', payload)
        format_entry = 'H'
    if type_name == 'padding':
        return payload, hexlify(payload)
    if type_name == 'SessionTicket_TLS':
        return payload, hexlify(payload)
    if type_name == 'cipher_suites':
        format_entry = 'H'
    if type_name == 'supported_groups':
        format_entry = 'H'
    if type_name == 'signature_algorithms':
        format_entry = 'H'
    if type_name == 'cipher_suites':
        format_entry = 'H'
    if list_length:
        payload = payload[:list_length]
    while (len(payload) > 0):
        if type_name == 'server_name':
            _type, payload = unpacker('B', payload)
            format_entry = 'P'
        if type_name == 'application_layer_protocol_negotiation':
            format_entry = 'p'
        entry, payload = unpacker(format_entry, payload)
        entries.append(entry)
        if type_name == 'signature_algorithms':
            pretty_entries.append('{0}-{1}'.
                                  format(pretty_name
                                         ('signature_algorithms_hash',
                                          entry >> 8),
                                         pretty_name('signature_algorithms_signature',
                                                     entry % 256)))
        else:
            if format_entry.lower() == 'p':
                pretty_entries.append(entry)
            else:
                pretty_entries.append(pretty_name(type_name, entry))
    return entries, pretty_entries


def unpacker(type_string, packet):
    """
    Returns network-order parsed data and the packet minus the parsed data.
    """
    if type_string.endswith('H'):
        length = 2
    if type_string.endswith('B'):
        length = 1
    if type_string.endswith('P'):  # 2 bytes for the length of the string
        length, packet = unpacker('H', packet)
        type_string = '{0}s'.format(length)
    if type_string.endswith('p'):  # 1 byte for the length of the string
        length, packet = unpacker('B', packet)
        type_string = '{0}s'.format(length)
    data = struct.unpack('!' + type_string, packet[:length])[0]
    if type_string.endswith('s'):
        data = ''.join(str(data))
    return data, packet[length:]


def pretty_name(name_type, name_value):
    """Returns the pretty name for type name_type."""
    if name_type in PRETTY_NAMES:
        if name_value in PRETTY_NAMES[name_type]:
            name_value = PRETTY_NAMES[name_type][name_value]
        else:
            name_value = '{0}: unknown value {1}'.format(name_value, name_type)
    else:
        name_value = 'unknown type: {0}'.format(name_type)
    return name_value


if __name__ == '__main__':
    pass
