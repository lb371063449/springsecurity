package com.rinbo.springsecurity.core.valid;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.awt.image.BufferedImage;

@Data
@AllArgsConstructor
public class ImageCode{
    private BufferedImage image;
    private String code;
    private long expireTime;
}
