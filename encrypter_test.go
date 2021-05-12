package encrypter

import (
	"reflect"
	"testing"
)

func TestEncrypter_hash(t *testing.T) {
	type fields struct {
		key string
	}
	type args struct {
		iv    string
		value string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			fields: fields{key: "qyk5OUGEoI3e7asY/ij+uMEeBnSxWTDS8LT7ExX1u88="},
			args:   args{iv: "", value: ""},
			want:   "794de6a7f3806fad54729599045b14a7b854702bbdd931c1deeff085e45b8d03",
		},
		{
			fields: fields{key: "qyk5OUGEoI3e7asY/ij+uMEeBnSxWTDS8LT7ExX1u88="},
			args:   args{iv: "aaa", value: ""},
			want:   "80a3ecfd25176b3a4e8a31a548d170ebab47fd2edd263c1c25ae5090b1604986",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEncrypter(tt.fields.key)

			if got := e.hash(tt.args.iv, tt.args.value); got != tt.want {
				t.Errorf("hash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncrypter_getJsonPayload(t *testing.T) {
	type fields struct {
		key string
	}
	type args struct {
		payload string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   Payload
	}{
		{
			fields: fields{key: "qyk5OUGEoI3e7asY/ij+uMEeBnSxWTDS8LT7ExX1u88="},
			args: args{payload: "eyJpdiI6IllXRmhZV0ZoWVdGaFlXRmhZV0ZoWVE9PSIsInZhbHVlIjoiYSIsIm1hYyI6IjNhMGZlNTFjOWMyMThhZGIzMjU5ZjVmNDc4MDUzMjVmNDE5NTRmMjE5NmNhNDJlY2QwNzNiNjUwMzI1YWJmMmMifQ=="},
			want: Payload{Iv: "YWFhYWFhYWFhYWFhYWFhYQ==", Value: "a", Mac: "3a0fe51c9c218adb3259f5f47805325f41954f2196ca42ecd073b650325abf2c"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Encrypter{
				key: tt.fields.key,
			}
			if got := e.getJsonPayload(tt.args.payload); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getJsonPayload() = %v, want %v", got, tt.want)
			}
		})
	}
}