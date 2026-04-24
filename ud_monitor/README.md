Dockeren belüli cmake-es build lépései:

1. aitia-sga/aitia nevű repo klónozása
2. cmake-userdata nevű mappába navigáls
3. "./start_env.sh" script futtatása linux rendszeren
     ez pull-olja dockerhub-ról az image-et és mount-olja a work directory-t
     majd elindítja a docker terminálját, ott kell kiadni a következő parancsokat:

    "cd mnt/userdata && mkdir build && cd build"
    
    "cmake .."
    
    "cmake --build ."

4. létre kell hozni a projekt mappájában egy build mappát és ott futtatni a cmake építést
