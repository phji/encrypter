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
			args:   args{payload: "eyJpdiI6IlliTVRuZXZVcDEyWlhRRWp4Vjd3TWc9PSIsInZhbHVlIjoiMTdCbkdvR3lOanNaOWxzMWZtYkJuUT09IiwibWFjIjoiMzJmODU1NmY1NDZkZDFlZTJlZjE2M2ZiOWNiODY2NDRlMTY5YTRhYTVlNmIxN2JjZWU1MGIzZTc1OWViZmQyNSJ9"},
			want:   Payload{Iv: "YbMTnevUp12ZXQEjxV7wMg==", Value: "17BnGoGyNjsZ9ls1fmbBnQ==", Mac: "32f8556f546dd1ee2ef163fb9cb86644e169a4aa5e6b17bcee50b3e759ebfd25"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEncrypter(tt.fields.key)
			if got := e.getJsonPayload(tt.args.payload); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getJsonPayload() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncrypter_Decrypt(t *testing.T) {
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
		want   string
	}{
		{
			name: "a",
			fields: fields{key: "qyk5OUGEoI3e7asY/ij+uMEeBnSxWTDS8LT7ExX1u88="},
			args:   args{payload: "eyJpdiI6IlliTVRuZXZVcDEyWlhRRWp4Vjd3TWc9PSIsInZhbHVlIjoiMTdCbkdvR3lOanNaOWxzMWZtYkJuUT09IiwibWFjIjoiMzJmODU1NmY1NDZkZDFlZTJlZjE2M2ZiOWNiODY2NDRlMTY5YTRhYTVlNmIxN2JjZWU1MGIzZTc1OWViZmQyNSJ9"},
			want:   "a",
		},
		{
			name: "empty",
			fields: fields{key: "qyk5OUGEoI3e7asY/ij+uMEeBnSxWTDS8LT7ExX1u88="},
			args:   args{payload: "eyJpdiI6InR3Z3pkQlJTNmQzMzJpUXo4ME5EZ0E9PSIsInZhbHVlIjoiYjVHY095alN2Ym1ZOEZWaUkyZW9tQT09IiwibWFjIjoiODIwMjE3NjQwOTZmMzM2MTgzMDIwYTY0NGQwOWI4NmRiNjNmN2Q4MjliMDg1NWQ4OWVkZTQwZDgzZjg2MzU2ZCJ9"},
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEncrypter(tt.fields.key)
			if got := e.Decrypt(tt.args.payload); got != tt.want {
				t.Errorf("Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncrypter_Encrypt(t *testing.T) {
	type fields struct {
		key string
	}
	type args struct {
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
			args: args{value: ""},
			//  eyJpdiI6IklJWS8yRkZrMjIrT1hmbm9ZK1BVR2c9PSIsInZhbHVlIjoiRDc2MitvRWQwT1JaSUR1M0pJSXEydz09IiwibWFjIjoiMWYxOTBjODEwOTdiM2VlYWNiMzlkZmY2NzFlMGJkNzcyNzg5ZmM0NTUzODQ3NjVhNWVjYzVmYWE1OGJkZTg4ZSJ9
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEncrypter(tt.fields.key)

			if got := e.Decrypt(e.Encrypt(tt.args.value)); got != tt.want {
				t.Errorf("Encrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}