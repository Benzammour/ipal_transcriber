from transcriber.messages import IpalMessage, Activity
from transcribers.transcriber import Transcriber
import transcriber.settings as settings


class MqttTranscriber(Transcriber):
    _name = "mqtt"

    # _pkt_id_topic_map: (src, dst, mqtt_pkt_id) -> Topic
    _pkt_id_topic_map = {}

    _type_activity_map = {
        1: Activity.COMMAND,
        2: Activity.ACTION,
        3: Activity.INFORM,
        4: Activity.ACTION,
        5: Activity.ACTION,
        6: Activity.ACTION,
        7: Activity.COMMAND,
        8: Activity.INTERROGATE,
        9: Activity.INFORM,
        10: Activity.COMMAND,
        11: Activity.ACTION,
        12: Activity.INTERROGATE,
        13: Activity.INFORM,
        14: Activity.COMMAND
    }

    @classmethod
    def state_identifier(cls, msg, key):
        if msg.activity in [str(Activity.INTERROGATE), str(Activity.COMMAND)]:
            return "{}:{}".format(msg.dest, key)
        elif msg.activity in [str(Activity.INFORM), str(Activity.ACTION)]:
            return "{}:{}".format(msg.src, key)
        else:
            settings.logger.critical("Unknown activity {}".format(msg.activity))
            return "{}:{}".format(msg.src, key)

    def matches_protocol(self, pkt):
        return "MQTT" in pkt

    def parse_packet(self, pkt):
        src = "{}:{}".format(pkt["IP"].src, pkt["TCP"].srcport)
        dest = "{}:{}".format(pkt["IP"].dst, pkt["TCP"].dstport)

        res = []
        for mqtt_pkt in pkt.get_multiple_layers("MQTT"):

            next_id = self._id_counter.get_next_id()
            length = 2 + int(mqtt_pkt.len) # Layer.len returns payload size, header-size is fixed
            msg_type = int(mqtt_pkt.msgtype)
            activity = self._type_activity_map[msg_type]
            ts = float(pkt.sniff_time.timestamp())

            # Parse data:
            data = {}
            match msg_type:
                case 3: # Publish
                    topic = mqtt_pkt.topic
                    data[topic] = self.__bytearr_from_str(mqtt_pkt.msg).decode("utf-8")

                case 8: # Subscribe
                    topic = mqtt_pkt.topic
                    data[topic] = None
                    # Store the topic in self._pkt_id_topic_map for the corresponding SubACK
                    self._pkt_id_topic_map[(src, dest, mqtt_pkt.msgid)] = topic

                case 9: # SubACK
                    # To access the saved topic, we need to transpose src and dest:
                    topic = self._pkt_id_topic_map.pop((dest, src, mqtt_pkt.msgid))
                    data[topic] = None

            new_msg = IpalMessage(
                id=next_id,
                src=src,
                dest=dest,
                protocol=self._name,
                length=length,
                type=msg_type,
                activity=activity,
                responds_to=[],
                data=data,
                timestamp=ts,
            )

            # Save some information to set response_to later:
            new_msg._mqtt_msg_id = self.__parse_mqtt_pkt_id(mqtt_pkt)
            # For Connect, PubREC, PubREL, Subscribe, Unsub, PingREQ or Publish
            new_msg._add_to_request_queue = (msg_type in [1, 5, 6, 8, 10, 12]) or (msg_type == 3 and mqtt_pkt.qos in ['1', '2'])
            # For ConnACK, PubACK, PubREC, PubREL, PubCOMP, SubACK, UnsubACK, PingRESP
            new_msg._match_to_requests = msg_type in [2, 4, 5, 6, 7, 9, 11, 13]

            res.append(new_msg)

        return res


    def match_response(self, requests, response):
        match response.type:
            case 2: # ConnACK
                response.responds_to = [ipal_pkt.id for ipal_pkt in requests if ipal_pkt.type == 1]
                return [ipal_pkt for ipal_pkt in requests if ipal_pkt.type == 1]

            case 4 | 5 | 6 | 7 | 9 | 11: # MQTT QoS 1 & 2
                res_to_type = [0, 0, 0, 0, 3, 3, 5, 6, 0, 8, 0, 10][response.type]

                # every packet that responds to the ACK
                responds_to_packets = [ipal_pkt for ipal_pkt in requests 
                    if ipal_pkt.type == res_to_type 
                        and ipal_pkt._mqtt_msg_id == response._mqtt_msg_id 
                        and ipal_pkt.src == response.dest
                        and ipal_pkt.dest == response.src]

                # every id for each packet from above
                response.responds_to = [packet.id for packet in responds_to_packets]

                # make sure every ACK has a request
                assert len(response.responds_to) != 0, settings.logger.critical("Found no request for ACK!")

                # MQTT QoS 1 & 2
                if response.type == 4:  # PubACK
                    return responds_to_packets
                elif response.type in [7, 9, 11]:   # PubREC, PubREL, PubCOMP, SubACK, UnsubACK
                    return [ipal_pkt for ipal_pkt in requests
                        if ipal_pkt._mqtt_msg_id == response._mqtt_msg_id 
                            and (ipal_pkt.src == response.dest or ipal_pkt.src == response.src)
                            and (ipal_pkt.dest == response.dest or ipal_pkt.dest == response.src)]
                else:
                    return []

            case 13: # PingRESP
                # Choose the first PingRESP in the queue as the corresponding request:
                first_ping_req = next(ipal_pkt for ipal_pkt in requests if ipal_pkt.type == 12)
                if first_ping_req:
                    response.responds_to = [first_ping_req.id]
                    return [first_ping_req]
                else:
                    settings.logger.critical("Found no PingREQ for PingRESP!")
                    return []

            case _:
                settings.logger.critical("Somehow match_response() was called on a non-ACK/non-PingRESP!")
                return []


    @staticmethod
    def __bytearr_from_str(string):
        return bytes.fromhex(string.replace(":", ""))

    @staticmethod
    def __parse_mqtt_pkt_id(mqtt_pkt):
        match int(mqtt_pkt.msgtype):
            case 1 | 2 | 12 | 13 | 14: # Connect, ConnACK, PingREQ, PingRESP, Disconnect
                return None

            case 3: # Publish
                if mqtt_pkt.qos == '1' or mqtt_pkt.qos == '2':
                    return mqtt_pkt.msgid
                return None

            case 4 | 5 | 6 | 7| 8 | 9 | 10 | 11: # PubACK, PubREC, PubREL, PubCOMP, Subscribe, SubACK, Unsub, UnsubACK
                return mqtt_pkt.msgid
