all: nfd_face_mgmt_pb2.py db_storage_pb2.py

nfd_face_mgmt_pb2.py: nfd-face-mgmt.proto
	/usr/local/bin/protoc --python_out=. nfd-face-mgmt.proto

db_storage_pb2.py: db-storage.proto
	/usr/local/bin/protoc --python_out=. db-storage.proto

clean:
	rm -f nfd_face_mgmt_pb2.py
	rm -f db_storage_pb2.py
