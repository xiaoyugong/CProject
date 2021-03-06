/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: packet.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "packet.pb-c.h"
void   mydpi__packet__init
                     (Mydpi__Packet         *message)
{
  static const Mydpi__Packet init_value = MYDPI__PACKET__INIT;
  *message = init_value;
}
size_t mydpi__packet__get_packed_size
                     (const Mydpi__Packet *message)
{
  assert(message->base.descriptor == &mydpi__packet__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t mydpi__packet__pack
                     (const Mydpi__Packet *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &mydpi__packet__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t mydpi__packet__pack_to_buffer
                     (const Mydpi__Packet *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &mydpi__packet__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Mydpi__Packet *
       mydpi__packet__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Mydpi__Packet *)
     protobuf_c_message_unpack (&mydpi__packet__descriptor,
                                allocator, len, data);
}
void   mydpi__packet__free_unpacked
                     (Mydpi__Packet *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &mydpi__packet__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor mydpi__packet__field_descriptors[21] =
{
  {
    "ipPorto2Name",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Mydpi__Packet, ipporto2name),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "srcIp",
    2,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Mydpi__Packet, srcip),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "srcPort",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(Mydpi__Packet, has_srcport),
    offsetof(Mydpi__Packet, srcport),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "dstIp",
    4,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Mydpi__Packet, dstip),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "dstPort",
    5,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(Mydpi__Packet, has_dstport),
    offsetof(Mydpi__Packet, dstport),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "proto",
    6,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Mydpi__Packet, proto),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "srcPktNums",
    7,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(Mydpi__Packet, has_srcpktnums),
    offsetof(Mydpi__Packet, srcpktnums),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "srcBytes",
    8,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT64,
    offsetof(Mydpi__Packet, has_srcbytes),
    offsetof(Mydpi__Packet, srcbytes),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "dstPktNums",
    9,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(Mydpi__Packet, has_dstpktnums),
    offsetof(Mydpi__Packet, dstpktnums),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "dstBytes",
    10,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT64,
    offsetof(Mydpi__Packet, has_dstbytes),
    offsetof(Mydpi__Packet, dstbytes),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "vlan",
    11,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(Mydpi__Packet, has_vlan),
    offsetof(Mydpi__Packet, vlan),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "host",
    12,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Mydpi__Packet, host),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "client",
    13,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Mydpi__Packet, client),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "server",
    14,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Mydpi__Packet, server),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "btHash",
    15,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Mydpi__Packet, bthash),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "info",
    16,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Mydpi__Packet, info),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "timestamp",
    17,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT64,
    offsetof(Mydpi__Packet, has_timestamp),
    offsetof(Mydpi__Packet, timestamp),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "httpURL",
    18,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Mydpi__Packet, httpurl),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "httpMethod",
    19,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Mydpi__Packet, httpmethod),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "srcMac",
    20,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Mydpi__Packet, srcmac),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "dstMac",
    21,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Mydpi__Packet, dstmac),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned mydpi__packet__field_indices_by_name[] = {
  14,   /* field[14] = btHash */
  12,   /* field[12] = client */
  9,   /* field[9] = dstBytes */
  3,   /* field[3] = dstIp */
  20,   /* field[20] = dstMac */
  8,   /* field[8] = dstPktNums */
  4,   /* field[4] = dstPort */
  11,   /* field[11] = host */
  18,   /* field[18] = httpMethod */
  17,   /* field[17] = httpURL */
  15,   /* field[15] = info */
  0,   /* field[0] = ipPorto2Name */
  5,   /* field[5] = proto */
  13,   /* field[13] = server */
  7,   /* field[7] = srcBytes */
  1,   /* field[1] = srcIp */
  19,   /* field[19] = srcMac */
  6,   /* field[6] = srcPktNums */
  2,   /* field[2] = srcPort */
  16,   /* field[16] = timestamp */
  10,   /* field[10] = vlan */
};
static const ProtobufCIntRange mydpi__packet__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 21 }
};
const ProtobufCMessageDescriptor mydpi__packet__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "mydpi.packet",
  "Packet",
  "Mydpi__Packet",
  "mydpi",
  sizeof(Mydpi__Packet),
  21,
  mydpi__packet__field_descriptors,
  mydpi__packet__field_indices_by_name,
  1,  mydpi__packet__number_ranges,
  (ProtobufCMessageInit) mydpi__packet__init,
  NULL,NULL,NULL    /* reserved[123] */
};
