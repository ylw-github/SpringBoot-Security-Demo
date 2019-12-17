package com.ylw.springboot.security.entity;


public class Permission {
	private Integer id;
	// 权限名称
	private String permName;
	// 权限标识
	private String permTag;
	// 请求url
	private String url;

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getPermName() {
		return permName;
	}

	public void setPermName(String permName) {
		this.permName = permName;
	}

	public String getPermTag() {
		return permTag;
	}

	public void setPermTag(String permTag) {
		this.permTag = permTag;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	@Override
	public String toString() {
		return "Permission{" +
				"id=" + id +
				", permName='" + permName + '\'' +
				", permTag='" + permTag + '\'' +
				", url='" + url + '\'' +
				'}';
	}
}
