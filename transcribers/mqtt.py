from transcriber.messages import IpalMessage, Activity
from transcribers.transcriber import Transcriber
import transcriber.settings as settings


class MqttTranscriber(Transcriber):
    _name = "mqtt"

    _func_to_addr_space = {
        1: "command",
        2: "action",
        3: "inform",
        4: "action",
        5: "action",
        6: "action",
        7: "command",
        8: "interrogate",
        9: "inform",
        10: "command",
        11: "action",
        12: "interrogate",
        13: "inform",
        14: "command"
    }

    @classmethod
    def state_identifier(cls, msg, key):
        if msg.activity in [Activity.INTERROGATE, Activity.COMMAND]:
            return "{}:{}".format(msg.dest, key)
        elif msg.activity in [Activity.INFORM, Activity.ACTION]:
            return "{}:{}".format(msg.src, key)
        else:
            settings.logger.critical("Unknown activity {}".format(msg.activity))
            return "{}:{}".format(msg.src, key)

    def matches_protocol(self, pkt):
        return "MQTT" in pkt

    def parse_packet(self, pkt):
        res = []

        id = self._id_counter.get_next_id()
        src = "{}:{}".format(pkt["IP"].src, pkt["TCP"].srcport)
        dest = "{}:{}".format(pkt["IP"].dst, pkt["TCP"].dstport)
        msg_type = int(pkt["MQTT"].msgtype)
        length = pkt["MQTT"].len
        activity = self._func_to_addr_space[msg_type]
        ts = float(pkt.sniff_time.timestamp())
        
        # Parse data:
        data = {}
        match msg_type:
            case 3: # Publish
                topic = pkt["MQTT"].topic
                data[topic] = self.__bytearr_from_str(pkt["MQTT"].msg).decode("utf-8")

            case 8: # Subscribe
                topic = pkt["MQTT"].topic
                data[topic] = None
            
            case 9: # SubACK
                topic = None
                data[topic] = None
        
        
        return [ IpalMessage(
            id=id,
            src=src,
            dest=dest,
            protocol=self._name,
            length=length,
            type=msg_type,
            activity=activity,
            responds_to=[],
            data=data,
            timestamp=ts,
        ) ]

    def __bytearr_from_str(self, string):
        return bytes.fromhex(string.replace(":", ""))



"""
        for i in range(len(adu_layers)):

            adu = adu_layers[i]
            mb = mb_layers[i]

            length = 6 + int(adu.len)

            if int(pkt["TCP"].srcport) == settings.MBTCP_PORT:  # Response

                code = int(mb.func_code)

                flow = (src, dest, int(adu.trans_id), code)

                m = IpalMessage(
                    id=self._id_counter.get_next_id(),
                    src=src + ":{}".format(adu.unit_id),
                    dest=dest,
                    timestamp=float(pkt.sniff_time.timestamp()),
                    protocol=self._name,
                    flow=flow,
                    length=length,
                    type=code,
                )

                if "exception_code" in mb.field_names:
                    self.transcribe_error_response(m, mb)
                elif code in [1, 2, 3, 4]:
                    self.transcribe_read_response(m, mb)
                elif code in [5, 6, 15, 16]:
                    self.transcribe_write_response(m, mb)
                else:
                    m.activity = Activity.INFORM  # NOTE maybe not an accurate activity
                    settings.logger.warning(
                        "Not implemented response function code {}".format(mb.func_code)
                    )  # msg.pdfdump()
                res.append(m)

            elif int(pkt["TCP"].dstport) == settings.MBTCP_PORT:  # Request
                code = int(mb.func_code)

                flow = (dest, src, int(adu.trans_id), code)

                m = IpalMessage(
                    id=self._id_counter.get_next_id(),
                    src=src,
                    dest=dest + ":{}".format(adu.unit_Id),
                    timestamp=float(pkt.sniff_time.timestamp()),
                    protocol=self._name,
                    flow=flow,
                    length=length,
                    type=code,
                )

                if code in [1, 2, 3, 4]:
                    self.transcribe_read_request(m, mb)
                elif code in [5, 6, 15, 16]:
                    self.transcribe_write_request(m, mb)
                elif code == 8:
                    self.transcribe_diagnostic(m, mb)
                elif code == 43:
                    self.transcribe_encapsulated_interface_transport_request(m, mb)
                else:
                    m.activity = (
                        Activity.INTERROGATE
                    )  # NOTE maybe not an appropriate activity
                    settings.logger.warning(
                        "Not implemented request function code {}".format(mb.func_code)
                    )
                res.append(m)

            else:

                settings.logger.critical(
                    "Unknown ports for Modbus ({}, {})".format(
                        pkt["TCP"].srcport, pkt["TCP"].dstport
                    )
                )
        """
