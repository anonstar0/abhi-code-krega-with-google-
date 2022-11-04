
// handeling events
/* this all code "handeling event " for flask socket io*/


var public_socket = io(); //initiate socket connection

//handling  event after connection
public_socket.on("connect", function () {
    public_socket.emit('connect_user', 'some cient connected')
});

//handle reciever event for recieving messages and also prettyfying("message ko sjana") the msg using css in js
public_socket.on("reciever", (msg) => {
    console.log('recieved msg: ', msg[0]);

    r_message = document.createElement('li');
    r_name = document.createElement('li');
    r_message.setAttribute(
        'style',
        'border-radius:20px; background-color:green; color: white; width:fit; height:fit; padding:2px 12px 2px 12px; margin:2px; font-family:"Lato",sans-serif; overflow-wrap:break-word; white-space: normal;',
    );
    r_name.setAttribute(
        'style',
        '  background-color:; color:black; width-fit height:fit; padding:2px 12px 2px 12px; margin:2px; font-family:"Lato",sans-serif; overflow-wrap:break-word; white-space: normal;',
    );

    let r_ul = document.getElementById('r_msg')
    var r_li = r_ul.insertAdjacentElement('afterbegin', r_message);
    var n_li = r_ul.insertAdjacentElement('afterbegin', r_name);
    n_li.innerHTML =` ${(msg[0])}: `;
    r_li.innerHTML = atob(msg[1]);

})

//when new user connect or disconnect show msg
public_socket.on('new_user',(display_msg)=>{
    client=document.getElementById("clients");
    client.style.color= display_msg[1];
    client.innerHTML=display_msg[0];

});

//fuck this event
//click download button to download image
public_socket.on('image_reciever',(data)=>{
    answer=confirm(`Get a image file from " ${data[0]} " want to download?`);
    let down=document.getElementById('d')
    if (answer==true){
        window.location.reload();//reload window
        down.click()

    }
    else{
        console.log(answer)
    }
    
})

// proccessing send button




// when user click send button using mouse (send msg)
function go() {

    let text = document.getElementById("take_input").value;


    if (text !== "") {
        s_message = document.createElement('li');
        s_message.setAttribute(
            'style',
            'border-radius:20px; background-color:salmon; color: white; width:fit; height:fit; padding:2px 12px 2px 12px; margin:2px; font-family:Lato,sans-serif;',
        );
        let s_ul = document.getElementById('s_msg')
        var s_li = s_ul.insertAdjacentElement('afterbegin', s_message);
        s_li.innerHTML = text;
        text=btoa(text);
        public_socket.emit("message", text);
        document.getElementById("take_input").value = "";

    }

}

// when user click send button using enter key(send msg)
document.addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
        // Enter key was hit
        let text = document.getElementById("take_input").value;
        if (text !== "") {
            s_message = document.createElement('li');
            s_message.setAttribute(
                'style',
                'border-radius:20px; background-color:salmon; color: white; width:fit; height:fit; padding:2px 12px 2px 12px; margin:2px; font-family:Lato,sans-serif;',
            );
            let s_ul = document.getElementById('s_msg')
            var s_li = s_ul.insertAdjacentElement('afterbegin', s_message);
            s_li.innerHTML = text;
            text = btoa(text);
            public_socket.emit("message", text);
            document.getElementById("take_input").value = "";

        }


    }
});

//function for toggle "file share" option 
function file_sender(){
    let file = document.getElementById("file_panel");
    
    if (file.style.display === "none") {
        file.style.display = "block";
    } 
    else {
        file.style.display = "none";
    }
    
}



// when window reload  or exit  show  user diconnect
window.onbeforeunload = function () {
    public_socket.emit('disconnect');
}

// handeling events end


/* close flashing message or error when cick on cross button */
//handle close msg and nav
function hide_msg(id){
  
    let div=document.getElementById(id);
    let div2 = document.getElementById('hd2');
    div.style.display = "none";   
    div2.style.display = "flex";
 

}

//use hamburger to show hide bars
function shownav(id){
    let div=document.getElementById(id);
    let div2 = document.getElementById('hd2');
 
    if (div.style.display === "none") {
        div.style.display = "block";
        div2.style.display = "none";

    }
    else {
        div.style.display = "none";
        div2.style.display = "flex";
    
    }

}

//reload window after md breakpoint
var width,height;
window.onresize = window.onload = function() {
    width = this.innerWidth;;

    if (width>=768 && width<770){
        window.location.reload();

    }
    }


//show selected image below name
var openFile = function (file) {
    var input = file.target;
    var reader = new FileReader();
    reader.onload = function () {
        var dataURL = reader.result;
        var output = document.getElementById('output');
        
        output.src = dataURL;
        output.style.display="block";
    };
    reader.readAsDataURL(input.files[0]);
};    