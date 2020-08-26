// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: trie.proto

package pb

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type Node struct {
	Val                  [][]byte `protobuf:"bytes,1,rep,name=val,proto3" json:"val,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Node) Reset()         { *m = Node{} }
func (m *Node) String() string { return proto.CompactTextString(m) }
func (*Node) ProtoMessage()    {}
func (*Node) Descriptor() ([]byte, []int) {
	return fileDescriptor_4a69962149106130, []int{0}
}
func (m *Node) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Node.Unmarshal(m, b)
}
func (m *Node) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Node.Marshal(b, m, deterministic)
}
func (m *Node) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Node.Merge(m, src)
}
func (m *Node) XXX_Size() int {
	return xxx_messageInfo_Node.Size(m)
}
func (m *Node) XXX_DiscardUnknown() {
	xxx_messageInfo_Node.DiscardUnknown(m)
}

var xxx_messageInfo_Node proto.InternalMessageInfo

func (m *Node) GetVal() [][]byte {
	if m != nil {
		return m.Val
	}
	return nil
}

func init() {
	proto.RegisterType((*Node)(nil), "pb.Node")
}

func init() { proto.RegisterFile("trie.proto", fileDescriptor_4a69962149106130) }

var fileDescriptor_4a69962149106130 = []byte{
	// 69 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x2a, 0x29, 0xca, 0x4c,
	0xd5, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x2a, 0x48, 0x52, 0x92, 0xe0, 0x62, 0xf1, 0xcb,
	0x4f, 0x49, 0x15, 0x12, 0xe0, 0x62, 0x2e, 0x4b, 0xcc, 0x91, 0x60, 0x54, 0x60, 0xd6, 0xe0, 0x09,
	0x02, 0x31, 0x93, 0xd8, 0xc0, 0x8a, 0x8c, 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0x67, 0xfa, 0x19,
	0x77, 0x32, 0x00, 0x00, 0x00,
}
