# Define the struct
class MsgHeader
    attr_accessor :size, :key, :hash, :code, :index, :timestamp

    def initialize
        @size = 0
        @key = 0
        @hash = 0
        @code = 0
        @index = 0
        @timestamp = 0
    end
end

keys = []
decrypted_packets = []

# Encrypt function
def encrypt
    decrypted_packets.each do |packet|
        j = 4
        key = keys[packet.key << 1]
        while j < packet.size
            mapped_key = keys[((key % 256) << 1) + 1]
            case j & 3
            when 0
                packet[j] = packet[j] + (mapped_key << 1)
            when 1
                packet[j] = packet[j] - (mapped_key >> 3)
            when 2
                packet[j] = packet[j] + (mapped_key << 2)
            when 3
                packet[j] = packet[j] - (mapped_key >> 5)
            end
            j += 1
            key += 1
        end
    end
end

# Read keys function
def read_keys(file_path)
    begin
        file = File.open(file_path, "rb")
        keys = file.read
        file.close
    rescue => e
        puts "Failed to open the keys file"
        return false
    end
    return true
end

# Read data function
def read_data_file(file_path, packets)
    begin
        file = File.open(file_path, "rb")
        file_size = file.size
        data_raw = file.read
        file.close
    rescue => e
        puts "Failed to open the keys file"
        return 0
    end

    ptr = 0
    tmp_size = file_size
    while tmp_size > 0
        packet = MsgHeader.new
        packet.size = data_raw[ptr, 2].unpack("S<")[0]
        packet.key = data_raw[ptr + 2, 1].unpack("C")[0]
        packet.hash = data_raw[ptr + 3, 1].unpack("C")[0]
        packet.code = data_raw[ptr + 4, 2].unpack("s<")[0]
        packet.index = data_raw[ptr + 6, 2].unpack("s<")[0]
        packet.timestamp = data_raw[ptr + 8, 4].unpack("L<")[0]
        packets << packet
        ptr += packet.size
        tmp_size -= packet.size
    end
    return data_raw
end

# Main function
if __FILE__ == $0
    ret = read_keys(ARGV[0])
    decrypted_file_raw = read_data_file("./decoded.bin", decrypted_packets)
    encrypt
    File.open("./encoded.bin", "wb") do |file|
        file.write decrypted_file_raw
    end
end
