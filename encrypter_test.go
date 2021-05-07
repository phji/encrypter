package encrypter

import "testing"

func TestEncrypter_Supported(t *testing.T) {
	type fields struct {
		key    string
		cipher Cipher
	}
	type args struct {
		key    string
		cipher Cipher
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "16bit",
			args: args{key: "aaaaaaaaaaaaaaaa", cipher: AES_128_CBC},
			want: true,
		},
		{
			name: "not 16bit",
			args: args{key: "aaaaaaaaaaaaaaa", cipher: AES_128_CBC},
			want: false,
		},
		{
			name: "32bit",
			args: args{key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", cipher: AES_256_CBC},
			want: true,
		},
		{
			name: "not 32bit",
			args: args{key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", cipher: AES_256_CBC},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Encrypter{
				key:    tt.fields.key,
				cipher: tt.fields.cipher,
			}
			if got := e.Supported(tt.args.key, tt.args.cipher); got != tt.want {
				t.Errorf("Supported() = %v, want %v", got, tt.want)
			}
		})
	}
}
