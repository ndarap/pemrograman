import streamlit as st
import numpy as np
import pandas as pd
import pickle
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from tensorflow.keras.models import load_model # type: ignore



# Fungsi untuk memuat model dan scaler
def load_models(lstm_path, svm_path, scaler_path, feature_columns_path):
     # Load LSTM model
    lstm_model = load_model(lstm_path)
    with open(svm_path, 'rb') as svm_file:
        svm_classifier = pickle.load(svm_file)
    with open(scaler_path, 'rb') as scaler_file:
        scaler = pickle.load(scaler_file)
    with open(feature_columns_path, 'rb') as f:
        feature_columns = pickle.load(f)
    
    return svm_classifier, scaler, feature_columns


# Tentukan path untuk model, scaler, dan feature columns
lstm_path = '/workspaces/pemrograman/lstm_model.h5'
svm_path = '/workspaces/pemrograman/svm_classifier.pkl'
scaler_path = '/workspaces/pemrograman/scaler.pkl'
feature_columns_path = '/workspaces/pemrograman/feature_columns.pkl'

# Memuat model SVM, scaler, dan feature columns
svm_classifier, scaler, feature_columns = load_models(lstm_path, svm_path, scaler_path, feature_columns_path)

# Judul aplikasi
st.title("Aplikasi Prediksi Serangan Botnet IoT")

# Input dari pengguna
st.write("Masukkan data berikut:")

# Membuat form input untuk fitur sesuai dengan UNSW dataset
# Anda perlu menyesuaikan input ini dengan fitur-fitur yang digunakan dalam model Anda
pkSeqID = st.number_input("pkSeqID", min_value=0, value=3577246)
stime = st.number_input("stime", min_value=0, value=1526351547)
flgs = st.selectbox("flgs", ["e", "other_options"])  # Ganti "other_options" sesuai opsi flgs yang ada
flgs_number = st.number_input("flgs_number", min_value=0, value=1)
proto = st.selectbox("proto", ["udp", "tcp", "icmp"])  # Sesuaikan dengan opsi proto
proto_number = st.number_input("proto_number", min_value=0, value=3)
saddr = st.text_input("saddr", value='192.168.100.148')
sport = st.number_input("sport", min_value=0, value=41735)
daddr = st.text_input("daddr", value='8.8.8.8')
dport = st.number_input("dport", min_value=0, value=53)
pkts = st.number_input("pkts", min_value=0, value=30)
AR_P_Proto_P_DstIP = st.number_input("AR_P_Proto_P_DstIP", min_value=0.0, value=269.7210)
N_IN_Conn_P_DstIP = st.number_input("N_IN_Conn_P_DstIP", min_value=0, value=15)
N_IN_Conn_P_SrcIP = st.number_input("N_IN_Conn_P_SrcIP", min_value=0, value=20)
AR_P_Proto_P_Sport = st.number_input("AR_P_Proto_P_Sport", min_value=0.0, value=263.2270)
AR_P_Proto_P_Dport = st.number_input("AR_P_Proto_P_Dport", min_value=0.0, value=0.322581)
Pkts_P_State_P_Protocol_P_DestIP = st.number_input("Pkts_P_State_P_Protocol_P_DestIP", min_value=0, value=30)
Pkts_P_State_P_Protocol_P_SrcIP = st.number_input("Pkts_P_State_P_Protocol_P_SrcIP", min_value=0, value=12)
attack = st.selectbox("attack", [0, 1])  # 0: Normal, 1: Attack
category = st.selectbox("category", ["Normal", "Attack"])  # Sesuaikan dengan kategori yang ada

# Menggabungkan input menjadi dictionary
input_data = {
    'pkSeqID': pkSeqID,
    'stime': stime,
    'flgs': flgs,
    'flgs_number': flgs_number,
    'proto': proto,
    'proto_number': proto_number,
    'saddr': saddr,
    'sport': sport,
    'daddr': daddr,
    'dport': dport,
    'pkts': pkts,
    'AR_P_Proto_P_DstIP': AR_P_Proto_P_DstIP,
    'N_IN_Conn_P_DstIP': N_IN_Conn_P_DstIP,
    'N_IN_Conn_P_SrcIP': N_IN_Conn_P_SrcIP,
    'AR_P_Proto_P_Sport': AR_P_Proto_P_Sport,
    'AR_P_Proto_P_Dport': AR_P_Proto_P_Dport,
    'Pkts_P_State_P_Protocol_P_DestIP': Pkts_P_State_P_Protocol_P_DestIP,
    'Pkts_P_State_P_Protocol_P_SrcIP': Pkts_P_State_P_Protocol_P_SrcIP,
    'attack': attack,
    'category': category
    # Tambahkan fitur lainnya jika ada
}

# Tombol prediksi
if st.button("Prediksi"):
    # Membuat DataFrame dari input
    input_df = pd.DataFrame([input_data])
    
    # Mengonversi kolom kategorikal menjadi one-hot encoding
    input_df_encoded = pd.get_dummies(input_df)
    
    # Menambahkan kolom yang hilang sesuai dengan fitur pelatihan
    for col in feature_columns:
        if col not in input_df_encoded.columns:
            input_df_encoded[col] = 0
    
    # Reorder kolom agar sesuai dengan pelatihan
    input_df_encoded = input_df_encoded[feature_columns]
    
    # Melakukan scaling pada data input
    std_data = scaler.transform(input_df_encoded)
    
    # Melakukan prediksi menggunakan model SVM
    prediction = svm_classifier.predict(std_data)
    
    # Menampilkan hasil prediksi
    if prediction[0] == 'Normal':
        st.write("Hasil Prediksi: Data tidak menunjukkan serangan Botnet")
    else:
        st.write("Hasil Prediksi: Data menunjukkan serangan Botnet")
