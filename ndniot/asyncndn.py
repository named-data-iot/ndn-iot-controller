import asyncio
import threading
from typing import Union, Dict, List
from pyndn import Face, Interest, NetworkNack, Data, Name
import logging
from pyndn.meta_info import ContentType


async def fetch_data_packet(face: Face, interest: Interest) -> Union[Data, NetworkNack, None]:
    done = threading.Event()
    result = None

    def on_data(_interest, data: Data):
        nonlocal done, result
        logging.info("RECEIVING DATA")
        result = data
        done.set()

    def on_timeout(_interest):
        nonlocal done
        logging.info("TIME OUT")
        done.set()

    def on_network_nack(_interest, network_nack: NetworkNack):
        nonlocal done, result
        result = network_nack
        done.set()

    async def wait_for_event():
        ret = False
        while not ret:
            ret = done.wait(0.01)
            await asyncio.sleep(0.01)

    try:
        logging.info("EXPRESSING INTEREST")
        logging.info(interest.name)
        face.expressInterest(interest, on_data, on_timeout, on_network_nack)
        await wait_for_event()
        return result
    except (ConnectionRefusedError, BrokenPipeError) as error:
        return error

def decode_dict(msg) -> Dict[str, str]:
    """
    Generate a Dict from a specified Protobuf message.
    This function is used only to generate a printable table.
    That means not every field is covered in the result.
    """
    ret = {}
    for field in msg.DESCRIPTOR.fields:
        if field.type == field.TYPE_MESSAGE:
            # Ignore this field.
            # Manual processing needed.
            pass
        elif (field.type == field.TYPE_UINT32 or
              field.type == field.TYPE_UINT64):
            ret[field.name] = str(getattr(msg, field.name))
        elif field.type == field.TYPE_BYTES:
            ret[field.name] = getattr(msg, field.name).decode('utf-8')
    return ret


def decode_list(lst) -> List[Dict[str, str]]:
    """
    Generate a table for each item in the lst.
    """
    ret = []
    for item in lst:
        ret.append(decode_dict(item))
    return ret


def decode_name(name) -> str:
    """
    Convert a Protobuf Name to uri
    """
    ret = Name()
    for comp in name.component:
        ret.append(comp)
    return ret.toUri()


def decode_content_type(content_type) -> str:
    codeset = ["BLOB", "LINK", "KEY", "NACK"]
    if content_type <= 3:
        return codeset[content_type]
    else:
        return str(content_type)


def decode_nack_reason(reason) -> str:
    codeset = {0: 'NONE', 50: 'CONGESTION', 100: 'DUPLICATE', 150: 'NO_ROUTE'}
    if reason in codeset:
        return codeset[reason]
    else:
        return str(reason)

def connection_test(face):
    interest = Interest("/localhost/nfd/faces/events")
    interest.mustBeFresh = True
    interest.canBePrefix = True
    interest.interestLifetimeMilliseconds = 1000
    try:
        def empty(*_args, **_kwargs):
            pass

        face.expressInterest(interest, empty, empty, empty)
        return True
    except (ConnectionRefusedError, BrokenPipeError, OSError):
        return False
