const headerSet = (extension,res) => {
    if(extension == "png"){
        res.setHeader("Content-Type", "image/png")
    }
    else if(extension == "jpg"){
        res.setHeader("Content-Type", "image/jpg")
    }
    else if(extension == "jpeg" || extension == "jfif"){
        res.setHeader("Content-Type", "image/jpeg")
    }
    else if(extension == "mp4"){
        res.setHeader("Content-Type", "video/mp4")
    }
    else if(extension == "gif"){
        res.setHeader("Content-Type", "image/gif")
    }
    else if(extension == "mp3"){
        res.setHeader("Content-Type", "audio/mpeg")
    }
    else if(extension == "mkv"){
        res.setHeader("Content-Type", "video/avi")
    }
    else if(extension == "pdf"){
        res.setHeader("Content-Type", "application/pdf")
    }
}
module.exports = headerSet;